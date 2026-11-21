//! The engine is the Windissect CLI. The GUI never re-implements analysis: it
//! runs the same commands a developer would, so a result in the window is the
//! result on the command line. Everything here is resolved at runtime.

use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;

#[derive(Clone)]
pub struct Engine {
    /// `windissect.exe`, the Rust analysis binary.
    pub cli: PathBuf,
    /// The fleet driver (`windissect.exe` at the repository root), which owns
    /// symbol-server downloads. Absent outside a checkout.
    pub fleet: Option<PathBuf>,
    /// The repository, for its docs.
    pub repo: Option<PathBuf>,
    /// Where IR and outputs are written: %LOCALAPPDATA%\Windissect\workspace
    /// on Windows, ~/.local/share/Windissect/workspace elsewhere.
    pub workspace: PathBuf,
}

pub struct Run {
    pub text: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PdbInfo {
    pub pdb_name: Option<String>,
    pub key: Option<String>,
    pub url: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone)]
pub struct DllEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Clone)]
pub struct Doc {
    pub title: String,
    pub path: PathBuf,
}

fn is_windissect_repo(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("Cargo.toml"))
        .is_ok_and(|toml| toml.contains("name = \"windissect\""))
}

impl Engine {
    pub fn locate() -> Self {
        let exe = std::env::current_exe().unwrap_or_default();
        let exe_dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        let repo = exe_dir
            .ancestors()
            .find(|dir| is_windissect_repo(dir))
            .map(Path::to_path_buf);

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(bin) = std::env::var_os("WINDISSECT_BIN") {
            candidates.push(PathBuf::from(bin));
        }
        let cli_name = exe_name("windissect");
        if let Some(repo) = &repo {
            candidates.push(repo.join("target").join("release").join(&cli_name));
            candidates.push(repo.join("target").join("debug").join(&cli_name));
        }
        candidates.push(exe_dir.join(&cli_name));
        let cli = candidates
            .into_iter()
            .find(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from(&cli_name));

        // The fleet owns symbol-server downloads. Shipped beside the GUI as
        // windissect-fleet(.exe); in a checkout it is the root-level driver.
        let fleet = [
            Some(exe_dir.join(exe_name("windissect-fleet"))),
            repo.as_ref().map(|r| r.join(&cli_name)),
        ]
        .into_iter()
        .flatten()
        .find(|p| p.is_file() && *p != cli);

        // IR for one big DLL can run to gigabytes, so where it goes is a
        // setting ("workspace" in settings.json); the default is per user.
        let workspace = configured_workspace().unwrap_or_else(default_workspace);
        let _ = std::fs::create_dir_all(workspace.join("ir"));

        Self {
            cli,
            fleet,
            repo,
            workspace,
        }
    }

    pub fn ir_path(&self, stem: &str) -> PathBuf {
        self.workspace.join("ir").join(format!("{stem}.json"))
    }

    pub fn out_dir(&self, kind: &str, stem: &str) -> PathBuf {
        self.workspace.join(kind).join(stem)
    }

    /// Runs a program to completion without a console window and returns
    /// stdout and stderr together.
    pub fn run<I, S>(&self, program: &Path, args: I) -> Run
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(program);
        command.args(args).current_dir(&self.workspace);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        match command.output() {
            Ok(out) => {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.trim().is_empty() {
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push_str(&err);
                }
                Run { text }
            }
            Err(err) => Run {
                text: format!("could not start {}: {err}", program.display()),
            },
        }
    }

    /// Runs a program without a console window, sending each line of stdout
    /// and stderr to `lines` as it is printed. Returns whether it succeeded;
    /// a cancelled run returns false. `cancel` can kill it from any thread.
    pub fn stream(
        &self,
        program: &Path,
        args: &[String],
        lines: &async_channel::Sender<String>,
        cancel: &Cancel,
    ) -> bool {
        if cancel.is_cancelled() {
            return false;
        }
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(&self.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        // Its own process group, so cancelling can stop the analyzer the
        // fleet starts as well (see kill_tree).
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                let _ =
                    lines.send_blocking(format!("could not start {}: {err}", program.display()));
                return false;
            }
        };
        let readers = [
            child.stdout.take().map(|out| forward(out, lines.clone())),
            child.stderr.take().map(|err| forward(err, lines.clone())),
        ];
        let child = Arc::new(Mutex::new(child));
        cancel.attach(&child);
        // Polled rather than blocked on, so Cancel can take the lock and kill.
        let ok = loop {
            match child.lock().map(|mut c| c.try_wait()) {
                Ok(Ok(Some(status))) => break status.success(),
                Ok(Ok(None)) => std::thread::sleep(Duration::from_millis(40)),
                _ => break false,
            }
        };
        cancel.detach();
        for reader in readers.into_iter().flatten() {
            let _ = reader.join();
        }
        ok && !cancel.is_cancelled()
    }

    pub fn cli<I, S>(&self, args: I) -> Run
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run(&self.cli, args)
    }

    /// Where the module's PDB lives, from `windissect symbols --json` (no network).
    pub fn pdb_info(&self, module: &Path) -> Option<PdbInfo> {
        let run = self.cli([
            OsStr::new("symbols"),
            module.as_os_str(),
            OsStr::new("--json"),
        ]);
        let start = run.text.find('[')?;
        let reports: Vec<PdbInfo> = serde_json::from_str(&run.text[start..]).ok()?;
        reports.into_iter().next()
    }

    /// Every DLL in a System32, by name, and which System32 that was. On
    /// Windows it is this machine's. Elsewhere there is no System32 of our
    /// own, so it is the first Windows install found mounted, or `None`.
    pub fn system_dlls() -> (Option<PathBuf>, Vec<DllEntry>) {
        #[cfg(windows)]
        let root = Some(
            std::env::var_os("SystemRoot")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
                .join("System32"),
        );
        #[cfg(not(windows))]
        let root = mounted_system32(&mount_bases()).into_iter().next();
        let dlls = root.as_deref().map(Self::dlls_in).unwrap_or_default();
        (root, dlls)
    }

    /// Every DLL directly in `dir`, by name.
    pub fn dlls_in(dir: &Path) -> Vec<DllEntry> {
        let mut out: Vec<DllEntry> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                let is_dll = path
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"));
                let meta = entry.metadata().ok()?;
                (is_dll && meta.is_file()).then(|| DllEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    path,
                    size: meta.len(),
                })
            })
            .collect();
        out.sort_by_key(|d| d.name.to_ascii_lowercase());
        out
    }

    /// The repository's README and docs/*.md, titled by their first heading.
    pub fn docs(&self) -> Vec<Doc> {
        let Some(repo) = &self.repo else {
            return Vec::new();
        };
        let mut paths = vec![repo.join("README.md")];
        let mut more: Vec<PathBuf> = std::fs::read_dir(repo.join("docs"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(OsStr::to_str) == Some("md"))
            .collect();
        more.sort();
        paths.extend(more);
        paths
            .into_iter()
            .filter(|p| p.is_file())
            .map(|path| {
                let title = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| {
                        text.lines()
                            .find(|l| l.starts_with("# "))
                            .map(|l| l.trim_start_matches("# ").trim().to_string())
                    })
                    .unwrap_or_else(|| {
                        path.file_stem()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    });
                Doc { title, path }
            })
            .collect()
    }
}

/// Reads a pipe line by line on its own thread. Output is decoded lossily:
/// tools may print in the console code page.
fn forward<R: Read + Send + 'static>(
    pipe: R,
    lines: async_channel::Sender<String>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    if lines.send_blocking(line).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Kills a child and everything it started: the fleet runs the extractor
/// as its own child, which a plain kill would leave running. Uses Windows'
/// taskkill from SystemRoot; falls back to killing the child alone.
fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let taskkill = std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join("System32").join("taskkill.exe"))
            .filter(|p| p.is_file());
        if let Some(taskkill) = taskkill {
            let status = Command::new(taskkill)
                .args(["/T", "/F", "/PID", &child.id().to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            if status.is_ok_and(|s| s.success()) {
                return;
            }
        }
    }
    // The child leads its own process group (see `Engine::stream`), so a
    // negative PID reaches everything it started.
    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok_and(|s| s.success()) {
            let _ = child.wait();
            return;
        }
    }
    let _ = child.kill();
}

/// Stops a running job: kills the child process currently attached, and
/// tells the job not to start any further step.
#[derive(Clone, Default)]
pub struct Cancel {
    child: Arc<Mutex<Option<Arc<Mutex<Child>>>>>,
    cancelled: Arc<AtomicBool>,
}

impl Cancel {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(child) = self.child.lock().ok().and_then(|slot| slot.clone())
            && let Ok(mut child) = child.lock()
        {
            kill_tree(&mut child);
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn attach(&self, child: &Arc<Mutex<Child>>) {
        if let Ok(mut slot) = self.child.lock() {
            *slot = Some(child.clone());
        }
        // Cancelled between spawn and attach: kill it now.
        if self.is_cancelled()
            && let Ok(mut child) = child.lock()
        {
            kill_tree(&mut child);
        }
    }

    fn detach(&self) {
        if let Ok(mut slot) = self.child.lock() {
            *slot = None;
        }
    }
}

/// `name` with this platform's executable suffix: `.exe` on Windows, none
/// elsewhere.
fn exe_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// A directory from the environment, if it is set to an absolute path.
fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// `$HOME/<rest>`, for the XDG defaults.
fn home_join(rest: &str) -> Option<PathBuf> {
    env_dir("HOME").map(|home| home.join(rest))
}

/// Per-user configuration: `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or
/// `~/.config` elsewhere.
fn config_root() -> Option<PathBuf> {
    if cfg!(windows) {
        env_dir("APPDATA")
    } else {
        env_dir("XDG_CONFIG_HOME").or_else(|| home_join(".config"))
    }
}

/// Per-user data: `%LOCALAPPDATA%` on Windows, `$XDG_DATA_HOME` or
/// `~/.local/share` elsewhere.
fn data_root() -> Option<PathBuf> {
    if cfg!(windows) {
        env_dir("LOCALAPPDATA")
    } else {
        env_dir("XDG_DATA_HOME").or_else(|| home_join(".local/share"))
    }
}

pub fn settings_path() -> Option<PathBuf> {
    config_root().map(|dir| dir.join("Windissect").join("settings.json"))
}

fn read_settings() -> serde_json::Value {
    settings_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}))
}

pub fn default_workspace() -> PathBuf {
    data_root()
        .unwrap_or_else(std::env::temp_dir)
        .join("Windissect")
        .join("workspace")
}

fn configured_workspace() -> Option<PathBuf> {
    read_settings()
        .get("workspace")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Saves the workspace folder to settings.json, keeping every other key.
pub fn save_workspace(path: &Path) -> std::io::Result<()> {
    let Some(file) = settings_path() else {
        return Err(std::io::Error::other(
            "no per-user settings folder (APPDATA, XDG_CONFIG_HOME or HOME)",
        ));
    };
    let mut settings = read_settings();
    settings["workspace"] = serde_json::Value::String(path.display().to_string());
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        file,
        serde_json::to_string_pretty(&settings).unwrap_or_default(),
    )
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Where a Linux machine mounts drives, each holding one folder per drive:
/// WSL puts Windows' own drives under /mnt, and desktops put NTFS partitions
/// under /media/$USER or /run/media/$USER (bare /media on some distros).
#[cfg(not(windows))]
fn mount_bases() -> Vec<PathBuf> {
    let mut bases = vec![PathBuf::from("/mnt"), PathBuf::from("/media")];
    if let Some(user) = std::env::var_os("USER") {
        bases.push(Path::new("/media").join(&user));
        bases.push(Path::new("/run/media").join(&user));
    }
    bases
}

/// Every `<base>/<drive>/Windows/System32` that exists, in order of `bases`
/// then drive name, so WSL's /mnt/c comes first. Names are matched ignoring
/// case because NTFS mounts do not agree on whether `Windows` keeps its case.
#[cfg(any(not(windows), test))]
fn mounted_system32(bases: &[PathBuf]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for base in bases {
        let mut drives: Vec<PathBuf> = std::fs::read_dir(base)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        drives.sort();
        for drive in drives {
            if let Some(dir) =
                child_named(&drive, "windows").and_then(|w| child_named(&w, "system32"))
            {
                if !found.contains(&dir) {
                    found.push(dir);
                }
            }
        }
    }
    found
}

/// The subdirectory of `dir` called `name`, ignoring ASCII case.
#[cfg(any(not(windows), test))]
fn child_named(dir: &Path, name: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .find(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .map(|e| e.path())
        .filter(|p| p.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_mounted_system32_ignoring_case() {
        let root = std::env::temp_dir().join(format!("wd-mounts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mnt = root.join("mnt");
        let media = root.join("media");
        std::fs::create_dir_all(mnt.join("c/Windows/System32")).unwrap();
        std::fs::create_dir_all(mnt.join("d/data")).unwrap();
        std::fs::create_dir_all(mnt.join("wslg")).unwrap();
        std::fs::create_dir_all(media.join("Win11/WINDOWS/system32")).unwrap();
        std::fs::create_dir_all(media.join("half/Windows")).unwrap();
        std::fs::write(mnt.join("c/Windows/System32/kernel32.dll"), b"MZ").unwrap();
        std::fs::write(mnt.join("c/Windows/System32/notes.txt"), b"").unwrap();

        let found = mounted_system32(&[mnt.clone(), root.join("absent"), media.clone()]);
        assert_eq!(
            found,
            vec![
                mnt.join("c/Windows/System32"),
                media.join("Win11/WINDOWS/system32")
            ]
        );
        let dlls = Engine::dlls_in(&found[0]);
        assert_eq!(dlls.len(), 1);
        assert_eq!(dlls[0].name, "kernel32.dll");
        assert!(mounted_system32(&[root.join("absent")]).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
