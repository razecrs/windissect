//! Optional external decompiler adapters. Their output is always candidate-only.

use anyhow::{Context, Result};
use clap::ValueEnum;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DecompileScope {
    Selected,
    #[value(alias = "main")]
    Target,
    All,
    Helpers,
}

impl DecompileScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Target => "target",
            Self::All => "all",
            Self::Helpers => "helpers",
        }
    }
}

pub fn command(
    binary: &Path,
    out: &Path,
    ida: Option<&Path>,
    rva: Option<u32>,
    scope: DecompileScope,
) -> Result<()> {
    anyhow::ensure!(
        !matches!(scope, DecompileScope::Selected) || rva.is_some(),
        "--scope selected requires --rva"
    );
    crate::file_access::ensure_readable(binary)?;
    let out = absolute_path(out)?;
    let ida = ida
        .map(Path::to_path_buf)
        .or_else(find_ida)
        .context("IDA/Hex-Rays was not found; pass --ida or set IDA_PATH")?;
    let script = find_script()
        .context("scripts/ida-decompile.py was not found; set WINDISSECT_IDA_DECOMPILE_SCRIPT")?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let metadata = out.with_extension("decompile.json");
    let database = out.with_extension("i64");
    let log = out.with_extension("ida.log");

    println!("decompiler backend: {}", ida.display());
    println!("PDB loading: disabled");
    println!("output status: candidate pseudocode");
    println!("decompile scope: {}", scope.as_str());
    let mut process = Command::new(&ida);
    process
        .arg("-A")
        .arg("-c")
        .arg("-Opdb:off")
        .arg(format!("-L{}", log.display()))
        .arg(format!("-o{}", database.display()))
        .arg(format!("-S{}", script.display()))
        .arg(binary)
        .env("WINDISSECT_DECOMPILE_OUT", &out)
        .env("WINDISSECT_DECOMPILE_META", &metadata)
        .env("WINDISSECT_DECOMPILE_SCOPE", scope.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(rva) = rva {
        println!("requested function: RVA 0x{rva:08X}");
        process.env("WINDISSECT_DECOMPILE_RVA", format!("0x{rva:X}"));
    }
    let status = process
        .status()
        .with_context(|| format!("launch {}", ida.display()))?;
    anyhow::ensure!(
        status.success(),
        "IDA decompiler exited with {status}; see {}",
        log.display()
    );
    println!("wrote candidate pseudocode to {}", out.display());
    println!("wrote decompiler provenance to {}", metadata.display());
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub fn find_ida() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("IDA_PATH").map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }

    #[cfg(windows)]
    {
        let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from)?;
        let mut installations = std::fs::read_dir(program_files)
            .ok()?
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("IDA Professional")
            })
            .map(|entry| entry.path().join("idat.exe"))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        installations.sort();
        installations.pop()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn find_script() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("WINDISSECT_IDA_DECOMPILE_SCRIPT").map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }
    let current_dir = std::env::current_dir().ok();
    let current_exe = std::env::current_exe().ok();
    let repo_from_target = current_exe
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    [current_dir, repo_from_target]
        .into_iter()
        .flatten()
        .map(|root| root.join("scripts").join("ida-decompile.py"))
        .find(|path| path.is_file())
}
