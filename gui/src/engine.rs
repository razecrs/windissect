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
    /// Where IR and outputs are written: %LOCALAPPDATA%\Windissect\workspace.
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
        if let Some(repo) = &repo {
            candidates.push(repo.join("target").join("release").join("windissect.exe"));
            candidates.push(repo.join("target").join("debug").join("windissect.exe"));
        }
        candidates.push(exe_dir.join("windissect.exe"));
        let cli = candidates
            .into_iter()
            .find(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("windissect.exe"));

        // The fleet owns symbol-server downloads. Shipped beside the GUI as
        // windissect-fleet.exe; in a checkout it is the root-level driver.
        let fleet = [
            Some(exe_dir.join("windissect-fleet.exe")),
            repo.as_ref().map(|r| r.join("windissect.exe")),
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

    /// Every DLL in this machine's System32, by name.
    pub fn system_dlls() -> Vec<DllEntry> {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32");
        let mut out: Vec<DllEntry> = std::fs::read_dir(&root)
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

fn settings_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|dir| PathBuf::from(dir).join("Windissect").join("settings.json"))
}

fn read_settings() -> serde_json::Value {
    settings_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}))
}

pub fn default_workspace() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
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
        return Err(std::io::Error::other("APPDATA is not set"));
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
