//! Electron application inspection: host binaries, `.asar` archives, loader
//! `index.js` exact original shapes, relied-upon Electron APIs, and IPC
//! channels.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use goblin::Object;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::asar::{self, AsarHeaderInfo};
use crate::electron_js::{self, ApiProvenance, ElectronLoaderRecord, LoaderInput, ScriptRole};
use crate::model::{
    BinaryInfo, Claim, ClaimStatus, ClaimSubject, Confidence, Coverage, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Kind, Proof,
    ProofObligation, Provenance, SCHEMA_VERSION, Signature, Symbol, Usability,
};

// ---------------------------------------------------------------------------
// IR types
// ---------------------------------------------------------------------------

/// Top-level Electron application dissection attached to [`Database::electron`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectronApp {
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    pub electron_version: ElectronVersionInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_binaries: Vec<ElectronBinaryInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_info: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archives: Vec<ElectronArchiveInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loaders: Vec<ElectronLoaderRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub electron_apis: Vec<ElectronApiUsage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipc_channels: Vec<IpcChannelUsage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_ipc_sites: Vec<DynamicIpcSite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_bridges: Vec<ContextBridgeRecord>,
}

/// Resolved and observed Electron / Chromium versions across binary & manifests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectronVersionInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chromium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_declared: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<VersionObservation>,
}

/// One concrete version observation paired with where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionObservation {
    pub source_path: String,
    pub kind: String,
    pub version: String,
    pub raw: String,
}

/// Host executable / Electron framework binary metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectronBinaryInfo {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub electron_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chromium_version: Option<String>,
}

/// Summary and entry table for one discovered `.asar` archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectronArchiveInfo {
    pub path: String,
    pub role: String,
    pub sha256: String,
    pub byte_size: u64,
    pub unpacked_dir_present: bool,
    pub header: AsarHeaderInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_json: Option<PackageSummary>,
    pub file_count: usize,
    pub packed_count: usize,
    pub unpacked_count: usize,
    pub symlink_count: usize,
    pub total_uncompressed_bytes: u64,
    pub integrity_checked: usize,
    pub integrity_valid: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub integrity_mismatches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<ArchiveEntrySummary>,
}

/// Compact per-entry summary inside an `.asar` archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEntrySummary {
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default)]
    pub unpacked: bool,
    #[serde(default)]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_hash: Option<String>,
}

/// Selected metadata parsed from an app or module `package.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub electron_spec: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dev_dependencies: Vec<String>,
}

/// Aggregated Electron API usage relied on across inspected scripts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectronApiUsage {
    pub api: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    pub provenance: ApiProvenance,
    pub call_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<ApiSourceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSourceRef {
    pub source: String,
    pub role: ScriptRole,
    pub count: usize,
}

/// Aggregated IPC channel observed via literals, constants, enums, or whitelists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcChannelUsage {
    pub channel: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directions: Vec<String>,
    pub resolution: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbol_names: Vec<String>,
    pub call_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<IpcSourceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcSourceRef {
    pub source: String,
    pub role: ScriptRole,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
    pub count: usize,
}

/// IPC call site whose channel argument was computed dynamically at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicIpcSite {
    pub operation: String,
    pub expression: String,
    pub count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

/// `contextBridge.exposeInMainWorld(api_key, ...)` surface discovered in preloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBridgeRecord {
    pub api_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public CLI & library entrypoints
// ---------------------------------------------------------------------------

/// Dissect an Electron app (install directory, `.asar`, loader `index.js`, or host
/// executable) and write a Windissect IR JSON database.
pub fn electron_command(target: &Path, out: &Path, unpack_dir: Option<&Path>) -> Result<()> {
    let report = inspect_target(target, unpack_dir)?;
    let json = serde_json::to_vec_pretty(&report)?;
    crate::diff::atomic_write(out, &json)?;

    let el = report.electron.as_ref().expect("electron report populated");
    let ver = el.electron_version.resolved.as_deref().unwrap_or("unknown");
    let unpacked_note = unpack_dir.map_or_else(String::new, |dir| {
        format!(", unpacked -> {}", dir.display())
    });
    println!(
        "{}: Electron {} ({} archives, {} loaders, {} APIs, {} IPC channels, {} bridges){} -> {}",
        report.binary.file,
        ver,
        el.archives.len(),
        el.loaders.len(),
        el.electron_apis.len(),
        el.ipc_channels.len(),
        el.context_bridges.len(),
        unpacked_note,
        out.display()
    );
    Ok(())
}

/// Dissect `target` into a complete [`Database`] IR in memory (used by CLI & tests).
pub fn inspect_target(target: &Path, unpack_dir: Option<&Path>) -> Result<Database> {
    if !target.exists() {
        bail!("target does not exist: {}", target.display());
    }
    let discovery = discover_artifacts(target)?;
    if discovery.asars.is_empty()
        && discovery.loaders.is_empty()
        && discovery.host_binaries.is_empty()
        && discovery.unpacked_scripts.is_empty()
    {
        bail!(
            "{} does not look like an Electron app, .asar archive, or JS loader",
            target.display()
        );
    }

    let mut state = AssemblyState::new(discovery.root_display.clone(), discovery.display_name);
    for bin in &discovery.host_binaries {
        inspect_host_binary(&discovery.root, bin, &mut state);
    }
    for manifest in &discovery.version_files {
        inspect_loose_version_file(&discovery.root, manifest, &mut state);
    }
    for pkg in &discovery.package_manifests {
        inspect_disk_package_json(&discovery.root, pkg, &mut state);
    }

    let mut loader_paths_seen = BTreeSet::new();
    for asar_path in &discovery.asars {
        process_asar(
            &discovery.root,
            asar_path,
            unpack_dir,
            &mut loader_paths_seen,
            &mut state,
        )?;
    }
    for loader_path in &discovery.loaders {
        process_disk_loader(
            &discovery.root,
            loader_path,
            unpack_dir,
            &mut loader_paths_seen,
            &mut state,
        )?;
    }
    for script_path in &discovery.unpacked_scripts {
        process_unpacked_script(&discovery.root, script_path, &mut state);
    }

    Ok(state.into_database())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

struct Discovery {
    root: PathBuf,
    root_display: String,
    display_name: String,
    host_binaries: Vec<PathBuf>,
    asars: Vec<PathBuf>,
    loaders: Vec<PathBuf>,
    version_files: Vec<PathBuf>,
    package_manifests: Vec<PathBuf>,
    unpacked_scripts: Vec<PathBuf>,
}

const SKIP_DIRS: &[&str] = &[
    "locales",
    "cache",
    "gpucache",
    "code cache",
    "dawngraphitecache",
    "dawnwebgpucache",
    "blob_storage",
    "session storage",
    "local storage",
    "indexeddb",
    "logs",
    ".git",
    "target",
    "__pycache__",
];

fn discover_artifacts(target: &Path) -> Result<Discovery> {
    let canonical = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    if canonical.is_file() {
        return discover_from_file(&canonical);
    }
    discover_from_dir(&canonical)
}

fn discover_from_file(file: &Path) -> Result<Discovery> {
    let parent = file.parent().unwrap_or_else(|| Path::new("."));
    let file_name = file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("electron-target")
        .to_string();
    let mut disc = Discovery {
        root: parent.to_path_buf(),
        root_display: normalize_path(parent),
        display_name: file_name.clone(),
        host_binaries: Vec::new(),
        asars: Vec::new(),
        loaders: Vec::new(),
        version_files: Vec::new(),
        package_manifests: Vec::new(),
        unpacked_scripts: Vec::new(),
    };

    if is_asar_candidate(file) {
        disc.asars.push(file.to_path_buf());
        attach_sibling_loader(parent, file, &mut disc);
        attach_ancestor_host(parent, &mut disc);
        return Ok(disc);
    }

    if is_js_path(file) {
        let content = fs::read(file).with_context(|| format!("read {}", file.display()))?;
        let text = String::from_utf8_lossy(&content);
        let findings = electron_js::analyze_script(&file_name, &text);
        disc.loaders.push(file.to_path_buf());
        let sibling_pkg = parent.join("package.json");
        if sibling_pkg.is_file() {
            disc.package_manifests.push(sibling_pkg);
        }
        // Attach referenced sibling `.asar` files such as `require('./core.asar')`.
        for spec in &findings.requires {
            if spec.to_ascii_lowercase().ends_with(".asar") {
                let target_asar = parent.join(spec);
                if target_asar.is_file() && !disc.asars.contains(&target_asar) {
                    disc.asars.push(target_asar);
                }
            }
        }
        attach_ancestor_host(parent, &mut disc);
        return Ok(disc);
    }

    if is_executable_candidate(file) {
        disc.host_binaries.push(file.to_path_buf());
        // If this executable sits inside an Electron app directory, inspect its dir too.
        if parent.join("resources").is_dir() || has_sibling_asar(parent) {
            return discover_from_dir(parent);
        }
        return Ok(disc);
    }

    bail!("unsupported file for Electron analysis: {}", file.display());
}

fn attach_sibling_loader(dir: &Path, asar_file: &Path, disc: &mut Discovery) {
    let asar_name = asar_file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let pkg = dir.join("package.json");
    let pkg_mentions_loader = pkg.is_file()
        && fs::read_to_string(&pkg)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("main")?.as_str().map(str::to_string))
            .is_some();
    if pkg.is_file() {
        disc.package_manifests.push(pkg);
    }
    let idx = dir.join("index.js");
    if idx.is_file()
        && let Ok(raw) = fs::read_to_string(&idx)
        && (raw.contains(asar_name) || pkg_mentions_loader)
    {
        disc.loaders.push(idx);
    }
}

/// Only walk up from well-known Electron sub-locations (`resources/` or `modules/`),
/// never arbitrarily across unrelated folders like `/tmp`.
fn attach_ancestor_host(start_dir: &Path, disc: &mut Discovery) {
    let name = start_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let app_root = if name == "resources" {
        start_dir.parent().map(Path::to_path_buf)
    } else if start_dir.ancestors().take(4).any(|p| {
        p.file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("modules"))
    }) {
        // Discord layout: <app_root>/modules/discord_desktop_core-1/discord_desktop_core
        start_dir
            .ancestors()
            .find(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("modules"))
            })
            .and_then(Path::parent)
            .map(Path::to_path_buf)
    } else {
        None
    };

    if let Some(root) = app_root
        && let Some(exe) = pick_main_host_binary(&root)
    {
        disc.host_binaries.push(exe);
        let build_info = root.join("resources").join("build_info.json");
        if build_info.is_file() {
            disc.version_files.push(build_info);
        }
    }
}

fn discover_from_dir(root: &Path) -> Result<Discovery> {
    let display_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("electron-app")
        .to_string();

    let mut asars = Vec::new();
    let mut loaders = Vec::new();
    let mut version_files = Vec::new();
    let mut package_manifests = Vec::new();
    let mut unpacked_app_dirs = Vec::new();
    let mut exe_candidates = Vec::new();

    walk_dir(
        root,
        0,
        &mut asars,
        &mut loaders,
        &mut version_files,
        &mut package_manifests,
        &mut unpacked_app_dirs,
        &mut exe_candidates,
    )?;

    // Check root/app-*/Contents for primary host binaries cleanly without scanning helper DLLs.
    let mut host_binaries = select_host_binaries(&exe_candidates);
    if host_binaries.is_empty()
        && let Some(exe) = pick_main_host_binary(root)
    {
        host_binaries.push(exe);
    }

    let mut unpacked_scripts = Vec::new();
    for app_dir in unpacked_app_dirs {
        collect_unpacked_js(&app_dir, 0, &mut unpacked_scripts)?;
    }

    asars.sort();
    asars.dedup();
    loaders.sort();
    loaders.dedup();
    version_files.sort();
    version_files.dedup();
    package_manifests.sort();
    package_manifests.dedup();
    unpacked_scripts.sort();
    unpacked_scripts.dedup();

    Ok(Discovery {
        root: root.to_path_buf(),
        root_display: normalize_path(root),
        display_name,
        host_binaries,
        asars,
        loaders,
        version_files,
        package_manifests,
        unpacked_scripts,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    dir: &Path,
    depth: usize,
    asars: &mut Vec<PathBuf>,
    loaders: &mut Vec<PathBuf>,
    version_files: &mut Vec<PathBuf>,
    package_manifests: &mut Vec<PathBuf>,
    unpacked_app_dirs: &mut Vec<PathBuf>,
    exe_candidates: &mut Vec<(PathBuf, u64)>,
) -> Result<()> {
    if depth > 7 {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries: Vec<_> = read_dir.filter_map(std::result::Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::file_name);

    let mut has_package_json = false;
    let mut has_index_js = false;
    let mut dir_asars = Vec::new();

    for entry in entries {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_ascii_lowercase();

        if meta.is_dir() {
            if SKIP_DIRS.contains(&lower.as_str()) {
                continue;
            }
            if lower == "node_modules" {
                let electron_pkg = path.join("electron").join("package.json");
                if electron_pkg.is_file() {
                    version_files.push(electron_pkg);
                }
                continue;
            }
            if lower.ends_with(".asar.unpacked") {
                continue;
            }
            walk_dir(
                &path,
                depth + 1,
                asars,
                loaders,
                version_files,
                package_manifests,
                unpacked_app_dirs,
                exe_candidates,
            )?;
            continue;
        }

        if is_asar_candidate(&path) && header_looks_like_asar(&path) {
            dir_asars.push(path.clone());
            asars.push(path);
        } else if lower == "index.js" || lower == "index.mjs" || lower == "index.cjs" {
            has_index_js = true;
            loaders.push(path);
        } else if lower == "package.json" {
            has_package_json = true;
            package_manifests.push(path);
        } else if lower == "build_info.json" || lower == "version" {
            version_files.push(path);
        } else if is_host_binary_candidate(&path, meta.len()) {
            exe_candidates.push((path, meta.len()));
        }
    }

    // If this directory holds an unpacked Electron app (`package.json` without any `.asar`
    // alongside, or `resources/app`), collect its JS files for API/IPC scanning as well.
    let dir_name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if has_package_json
        && dir_asars.is_empty()
        && (dir_name == "app" || depth <= 1 || has_index_js)
        && package_looks_like_electron_app(&dir.join("package.json"), dir)
    {
        unpacked_app_dirs.push(dir.to_path_buf());
        if let Some(main_script) = resolve_package_main(dir) {
            loaders.push(main_script);
        }
    }

    Ok(())
}

fn package_looks_like_electron_app(pkg_path: &Path, dir: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(pkg_path) else {
        return false;
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    let has_main = val.get("main").and_then(Value::as_str).is_some();
    let mentions_electron = has_electron_dep(&val)
        || dir.join("node_modules").join("electron").is_dir()
        || dir.parent().is_some_and(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("resources"))
        });
    has_main && mentions_electron
}

fn has_electron_dep(val: &Value) -> bool {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if val
            .get(section)
            .and_then(Value::as_object)
            .is_some_and(|m| m.contains_key("electron"))
        {
            return true;
        }
    }
    false
}

fn resolve_package_main(dir: &Path) -> Option<PathBuf> {
    let raw = fs::read_to_string(dir.join("package.json")).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    let main = val.get("main").and_then(Value::as_str)?;
    let candidate = dir.join(main);
    candidate.is_file().then_some(candidate)
}

fn collect_unpacked_js(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 5 {
        return Ok(());
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let path = entry.path();
        if meta.is_dir() {
            let name = entry.file_name();
            if name.to_string_lossy().eq_ignore_ascii_case("node_modules") {
                continue;
            }
            collect_unpacked_js(&path, depth + 1, out)?;
        } else if is_js_path(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn has_suffix_ci(text: &str, suffix: &str) -> bool {
    text.len() >= suffix.len()
        && text
            .get(text.len() - suffix.len()..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn is_asar_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    has_suffix_ci(name, ".asar")
        || has_suffix_ci(name, ".asar.backup")
        || has_suffix_ci(name, ".asar.bak")
        || has_suffix_ci(name, ".asar.orig")
}

fn header_looks_like_asar(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 16];
    file.read_exact(&mut head).is_ok() && asar::is_asar_prefix(&head)
}

fn is_js_path(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "js" | "mjs" | "cjs"))
}

fn is_executable_candidate(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        || path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n == "Electron Framework" || !n.contains('.'))
}

fn is_host_binary_candidate(path: &Path, len: u64) -> bool {
    if len < 256 * 1024 {
        return false;
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "update.exe" | "squirrel.exe" | "createdump.exe" | "updater_launcher.exe"
    ) || lower.starts_with("unins")
    {
        return false;
    }
    if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        || name == "Electron Framework"
    {
        return true;
    }
    // Extensionless Linux / macOS main executables in Contents/MacOS or root
    path.extension().is_none() && path.is_file()
}

fn select_host_binaries(candidates: &[(PathBuf, u64)]) -> Vec<PathBuf> {
    if candidates.is_empty() {
        return Vec::new();
    }
    // Prefer larger binaries first (real Chromium/Electron host binaries are tens of MB;
    // small launcher stubs are < 2 MB) and keep one primary binary per parent directory.
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut chosen = Vec::new();
    let mut seen_dirs = BTreeSet::new();
    for (path, size) in sorted {
        let dir = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        if chosen.is_empty() || (size >= 10 * 1024 * 1024 && !seen_dirs.contains(&dir)) {
            seen_dirs.insert(dir);
            chosen.push(path);
        }
    }
    chosen
}

fn pick_main_host_binary(root: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_file() && is_host_binary_candidate(&entry.path(), meta.len()) {
            candidates.push((entry.path(), meta.len()));
        }
    }
    select_host_binaries(&candidates).into_iter().next()
}

fn has_sibling_asar(dir: &Path) -> bool {
    let sub = dir.join("resources");
    [dir, sub.as_path()].iter().any(|candidate| {
        fs::read_dir(candidate)
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| is_asar_candidate(&e.path()))
    })
}

// ---------------------------------------------------------------------------
// Host binary inspection (Electron / Chrome UA + PE VersionInfo)
// ---------------------------------------------------------------------------

fn extract_binary_sections(bytes: &[u8]) -> (Option<String>, Vec<&[u8]>, Vec<&[u8]>) {
    let mut machine = None;
    let mut rdata_slices: Vec<&[u8]> = Vec::new();
    let mut rsrc_slices: Vec<&[u8]> = Vec::new();

    if let Ok(obj) = Object::parse(bytes) {
        match obj {
            Object::PE(pe) => {
                machine = Some(
                    match pe.header.coff_header.machine {
                        0x8664 => "x86_64",
                        0x014c => "x86",
                        0xAA64 => "arm64",
                        _ => "pe-unknown",
                    }
                    .to_string(),
                );
                for sec in &pe.sections {
                    let name = sec.name().unwrap_or_default();
                    let start = sec.pointer_to_raw_data as usize;
                    let end = start
                        .saturating_add(sec.size_of_raw_data as usize)
                        .min(bytes.len());
                    if start < end {
                        if matches!(name, ".rdata" | ".data") {
                            rdata_slices.push(&bytes[start..end]);
                        } else if name == ".rsrc" {
                            rsrc_slices.push(&bytes[start..end]);
                        }
                    }
                }
            }
            Object::Elf(elf) => {
                machine = Some(format!("elf-0x{:x}", elf.header.e_machine));
                for sh in &elf.section_headers {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
                        && matches!(name, ".rodata" | ".data")
                        && let Ok(start) = usize::try_from(sh.sh_offset)
                        && let Ok(len) = usize::try_from(sh.sh_size)
                        && let Some(slice) =
                            bytes.get(start..start.saturating_add(len).min(bytes.len()))
                    {
                        rdata_slices.push(slice);
                    }
                }
            }
            Object::Mach(goblin::mach::Mach::Binary(mach)) => {
                machine = Some(format!("macho-0x{:x}", mach.header.cputype));
                for seg in &mach.segments {
                    if let Ok(sections) = seg.sections() {
                        for (sec, _) in sections {
                            if matches!(sec.name().unwrap_or_default(), "__cstring" | "__const")
                                && let Ok(len) = usize::try_from(sec.size)
                                && let Some(slice) = bytes.get(
                                    sec.offset as usize
                                        ..(sec.offset as usize)
                                            .saturating_add(len)
                                            .min(bytes.len()),
                                )
                            {
                                rdata_slices.push(slice);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    (machine, rdata_slices, rsrc_slices)
}

fn inspect_host_binary(root: &Path, path: &Path, state: &mut AssemblyState) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    let rel = rel_display(root, path);
    let sha256 = crate::hex::lower(&Sha256::digest(&bytes));
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let (machine, rdata_slices, rsrc_slices) = extract_binary_sections(&bytes);

    let mut electron_version = find_prefixed_version(&rdata_slices, b"Electron/", false);
    if electron_version.is_none() {
        electron_version = find_prefixed_version(&[&bytes], b"Electron/", false);
    }
    let mut chromium_version = find_prefixed_version(&rdata_slices, b"Chrome/", true);
    if chromium_version.is_none() {
        chromium_version = find_prefixed_version(&[&bytes], b"Chrome/", true);
    }

    let rsrc_fallback = [&bytes[..]];
    let ver_strings = extract_pe_version_strings(if rsrc_slices.is_empty() {
        &rsrc_fallback
    } else {
        rsrc_slices.as_slice()
    });
    let product_name = ver_strings.get("ProductName").cloned();
    let product_version = ver_strings.get("ProductVersion").cloned();
    let file_version = ver_strings.get("FileVersion").cloned();

    if state.app_name.is_none()
        && let Some(pn) = &product_name
        && !pn.eq_ignore_ascii_case("electron")
    {
        state.app_name = Some(pn.clone());
    }
    if state.app_version.is_none() {
        state.app_version = product_version.clone().or_else(|| file_version.clone());
    }

    if let Some(ev) = &electron_version {
        state.version_sources.push(VersionObservation {
            source_path: rel.clone(),
            kind: "binary-user-agent".into(),
            version: ev.clone(),
            raw: format!("Electron/{ev}"),
        });
        if state.runtime_electron.is_none() {
            state.runtime_electron = Some(ev.clone());
        }
    }
    if product_name
        .as_deref()
        .is_some_and(|n| n.eq_ignore_ascii_case("electron"))
        && let Some(pv) = &product_version
        && is_semver_like(pv)
    {
        state.version_sources.push(VersionObservation {
            source_path: rel.clone(),
            kind: "pe-product-version".into(),
            version: pv.clone(),
            raw: pv.clone(),
        });
        if state.runtime_electron.is_none() {
            state.runtime_electron = Some(pv.clone());
        }
    }
    if let Some(cv) = &chromium_version
        && state.chromium_version.is_none()
    {
        state.chromium_version = Some(cv.clone());
    }

    state.host_binaries.push(ElectronBinaryInfo {
        path: rel,
        sha256,
        size,
        machine,
        product_name,
        product_version,
        file_version,
        electron_version,
        chromium_version,
    });
}

fn find_prefixed_version(slices: &[&[u8]], prefix: &[u8], four_part: bool) -> Option<String> {
    for slice in slices {
        let mut pos = 0usize;
        while let Some(rel_idx) = slice[pos..].windows(prefix.len()).position(|w| w == prefix) {
            let start = pos + rel_idx + prefix.len();
            let mut end = start;
            let limit = (start + 48).min(slice.len());
            while end < limit {
                let b = slice[end];
                if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
                    end += 1;
                } else {
                    break;
                }
            }
            if let Ok(candidate) = std::str::from_utf8(&slice[start..end]) {
                let valid = if four_part {
                    is_four_part_version(candidate)
                } else {
                    is_semver_like(candidate)
                };
                if valid {
                    return Some(candidate.to_string());
                }
            }
            pos = start;
        }
    }
    None
}

fn is_semver_like(s: &str) -> bool {
    let core = s.split('-').next().unwrap_or(s);
    let mut parts = core.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !a.is_empty()
        && !b.is_empty()
        && !c.is_empty()
        && a.bytes().all(|x| x.is_ascii_digit())
        && b.bytes().all(|x| x.is_ascii_digit())
        && c.bytes().all(|x| x.is_ascii_digit())
}

fn is_four_part_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(p1), Some(p2), Some(p3), Some(p4), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    [p1, p2, p3, p4]
        .iter()
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn extract_pe_version_strings(slices: &[&[u8]]) -> BTreeMap<String, String> {
    // UTF-16LE `StringFileInfo`
    const NEEDLE: &[u8] =
        b"S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00";
    let mut out = BTreeMap::new();
    for slice in slices {
        let Some(pos) = slice.windows(NEEDLE.len()).position(|w| w == NEEDLE) else {
            continue;
        };
        // Header is 6 bytes before key (`wLength`, `wValueLength`, `wType`).
        if pos < 6 {
            continue;
        }
        let sfi_start = pos - 6;
        let sfi_len = usize::from(u16::from_le_bytes([slice[sfi_start], slice[sfi_start + 1]]));
        let sfi_end = sfi_start.saturating_add(sfi_len).min(slice.len());
        let st_start = align4(pos + NEEDLE.len());
        if st_start + 6 >= sfi_end {
            continue;
        }
        // `StringTable` node (`040904b0` etc.)
        let st_len = usize::from(u16::from_le_bytes([slice[st_start], slice[st_start + 1]]));
        let st_end = st_start.saturating_add(st_len).min(sfi_end);
        let mut cursor = align4(st_start + 6 + utf16z_byte_len(&slice[st_start + 6..st_end]));
        while cursor + 6 < st_end {
            let entry_len = usize::from(u16::from_le_bytes([slice[cursor], slice[cursor + 1]]));
            let val_words = usize::from(u16::from_le_bytes([slice[cursor + 2], slice[cursor + 3]]));
            let wtype = u16::from_le_bytes([slice[cursor + 4], slice[cursor + 5]]);
            if entry_len < 6 {
                break;
            }
            let entry_end = cursor.saturating_add(entry_len).min(st_end);
            let key_bytes = &slice[cursor + 6..entry_end];
            let key_z = utf16z_byte_len(key_bytes);
            let key = decode_utf16le(&key_bytes[..key_z.saturating_sub(2)]);
            let val_start = align4(cursor + 6 + key_z);
            if wtype == 1 && val_words > 0 && val_start < entry_end {
                let val_end = val_start
                    .saturating_add(val_words.saturating_mul(2))
                    .min(entry_end);
                let val = decode_utf16le(&slice[val_start..val_end])
                    .trim_end_matches('\0')
                    .to_string();
                if !key.is_empty() && !val.is_empty() {
                    out.insert(key, val);
                }
            }
            cursor = align4(entry_end);
        }
        break;
    }
    out
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

const fn utf16z_byte_len(bytes: &[u8]) -> usize {
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            return i + 2;
        }
        i += 2;
    }
    bytes.len()
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let (chunks, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = chunks
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    String::from_utf16_lossy(&units)
}

// ---------------------------------------------------------------------------
// Manifests, ASAR archives, and loaders
// ---------------------------------------------------------------------------

fn inspect_loose_version_file(root: &Path, path: &Path, state: &mut AssemblyState) {
    let rel = rel_display(root, path);
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let lower = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if lower == "build_info.json"
        && let Ok(val) = serde_json::from_str::<Value>(&text)
    {
        if state.app_version.is_none() {
            state.app_version = val
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        state.build_info = Some(val);
    } else if lower == "version" {
        let trimmed = text.trim().trim_start_matches('v');
        if is_semver_like(trimmed) {
            state.version_sources.push(VersionObservation {
                source_path: rel,
                kind: "version-file".into(),
                version: trimmed.to_string(),
                raw: text.trim().to_string(),
            });
            if state.runtime_electron.is_none() {
                state.runtime_electron = Some(trimmed.to_string());
            }
        }
    } else if lower == "package.json"
        && let Ok(val) = serde_json::from_str::<Value>(&text)
        && val.get("name").and_then(Value::as_str) == Some("electron")
        && let Some(ver) = val.get("version").and_then(Value::as_str)
    {
        state.version_sources.push(VersionObservation {
            source_path: rel,
            kind: "node_modules-electron".into(),
            version: clean_semver_spec(ver).to_string(),
            raw: ver.to_string(),
        });
        if state.runtime_electron.is_none() {
            state.runtime_electron = Some(clean_semver_spec(ver).to_string());
        }
    }
}

fn inspect_disk_package_json(root: &Path, path: &Path, state: &mut AssemblyState) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    let rel_dir = path
        .parent()
        .map_or_else(String::new, |p| rel_display(root, p));
    let summary = summarize_package_json(&val);
    if let Some(spec) = &summary.electron_spec {
        let clean = clean_semver_spec(spec);
        if !clean.is_empty() {
            state.version_sources.push(VersionObservation {
                source_path: rel_display(root, path),
                kind: "package-json".into(),
                version: clean.to_string(),
                raw: spec.clone(),
            });
            if state.package_declared_electron.is_none() {
                state.package_declared_electron = Some(clean.to_string());
            }
        }
    }
    state.disk_packages.insert(rel_dir, summary);
}

fn summarize_package_json(val: &Value) -> PackageSummary {
    let mut deps = Vec::new();
    let mut dev_deps = Vec::new();
    let mut electron_spec = None;

    for (key, dst) in [
        ("dependencies", &mut deps),
        ("devDependencies", &mut dev_deps),
    ] {
        if let Some(obj) = val.get(key).and_then(Value::as_object) {
            for (pkg, ver) in obj {
                let ver_s = ver.as_str().unwrap_or_default();
                if pkg == "electron" && electron_spec.is_none() && !ver_s.is_empty() {
                    electron_spec = Some(ver_s.to_string());
                }
                dst.push(format!("{pkg}@{ver_s}"));
            }
        }
    }
    if electron_spec.is_none() {
        for section in ["optionalDependencies", "peerDependencies"] {
            if let Some(v) = val
                .get(section)
                .and_then(|s| s.get("electron"))
                .and_then(Value::as_str)
            {
                electron_spec = Some(v.to_string());
                break;
            }
        }
    }

    PackageSummary {
        name: val.get("name").and_then(Value::as_str).map(str::to_string),
        version: val
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: val
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        main: val.get("main").and_then(Value::as_str).map(str::to_string),
        package_type: val.get("type").and_then(Value::as_str).map(str::to_string),
        electron_spec,
        dependencies: deps,
        dev_dependencies: dev_deps,
    }
}

fn clean_semver_spec(spec: &str) -> &str {
    spec.trim()
        .trim_start_matches(['^', '~', '=', '>', '<', 'v'])
        .trim()
}

struct EntryCounts {
    packed: usize,
    unpacked: usize,
    symlinks: usize,
    total_bytes: u64,
}

fn collect_asar_entries(
    archive: &asar::AsarArchive,
    bytes: &[u8],
    rel_asar: &str,
    unpacked_root: Option<&Path>,
    pkg_summary: Option<&PackageSummary>,
    loader_paths_seen: &mut BTreeSet<String>,
    state: &mut AssemblyState,
) -> (EntryCounts, Vec<ArchiveEntrySummary>) {
    let pkg_name = pkg_summary.and_then(|p| p.name.as_deref());
    let pkg_main = pkg_summary.and_then(|p| p.main.as_deref());
    let normalized_main = pkg_main.map(|m| m.trim_start_matches("./"));

    let mut counts = EntryCounts {
        packed: 0,
        unpacked: 0,
        symlinks: 0,
        total_bytes: 0,
    };
    let mut entries_summary = Vec::with_capacity(archive.entries.len());

    for entry in &archive.entries {
        if entry.link.is_some() {
            counts.symlinks += 1;
        } else if entry.unpacked {
            counts.unpacked += 1;
        } else {
            counts.packed += 1;
        }
        counts.total_bytes = counts.total_bytes.saturating_add(entry.size);

        entries_summary.push(ArchiveEntrySummary {
            path: entry.path.clone(),
            size: entry.size,
            offset: entry.offset,
            unpacked: entry.unpacked,
            executable: entry.executable,
            link: entry.link.clone(),
            integrity_hash: entry.integrity.as_ref().map(|i| i.hash.clone()),
        });

        if !is_js_path(Path::new(&entry.path)) {
            continue;
        }
        let Some(script_bytes) = asar::entry_bytes(archive, bytes, entry)
            .map(std::borrow::Cow::Borrowed)
            .or_else(|| {
                (entry.unpacked)
                    .then_some(unpacked_root)
                    .flatten()
                    .and_then(|uroot| fs::read(uroot.join(&entry.path)).ok())
                    .map(std::borrow::Cow::Owned)
            })
        else {
            continue;
        };

        let is_entry = normalized_main == Some(entry.path.as_str()) || entry.path == "index.js";
        let full_source = format!("{rel_asar}/{}", entry.path);
        if is_entry && loader_paths_seen.insert(full_source.clone()) {
            let role = if entry.path == "index.js" {
                "asar-entrypoint"
            } else {
                "package-main"
            };
            let loader = electron_js::inspect_loader(
                &LoaderInput {
                    path: &full_source,
                    location: if entry.unpacked { "unpacked" } else { "asar" },
                    archive: Some(rel_asar),
                    role,
                    package_name: pkg_name,
                    package_main: pkg_main,
                },
                &script_bytes,
            );
            state.loaders.push(loader);
        }

        if let Ok(src) = std::str::from_utf8(&script_bytes) {
            let findings = electron_js::analyze_script(&full_source, src);
            state.record_script_findings(&full_source, findings);
        }
    }

    (counts, entries_summary)
}

fn process_asar(
    root: &Path,
    path: &Path,
    unpack_dir: Option<&Path>,
    loader_paths_seen: &mut BTreeSet<String>,
    state: &mut AssemblyState,
) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read ASAR {}", path.display()))?;
    let archive = asar::parse(&bytes).with_context(|| format!("parse ASAR {}", path.display()))?;
    let rel_asar = rel_display(root, path);
    let sha256 = crate::hex::lower(&Sha256::digest(&bytes));
    state
        .manifest_items
        .push((rel_asar.clone(), sha256.clone()));

    let unpacked_dir = PathBuf::from(format!("{}.unpacked", path.display()));
    let unpacked_root = unpacked_dir.is_dir().then_some(unpacked_dir.as_path());
    let integrity = asar::verify_integrity(&archive, &bytes, unpacked_root);

    if let Some(dir) = unpack_dir {
        let dest = dir.join("asars").join(asar_unpack_subdir(&rel_asar));
        asar::unpack(&archive, &bytes, &dest, unpacked_root)?;
    }

    let pkg_summary = asar::find_entry(&archive, "package.json")
        .and_then(|entry| asar::entry_bytes(&archive, &bytes, entry))
        .and_then(|raw| serde_json::from_slice::<Value>(raw).ok())
        .map(|val| summarize_package_json(&val));

    if let Some(pkg) = &pkg_summary {
        record_asar_package_metadata(&rel_asar, pkg, state);
    }

    let (counts, entries_summary) = collect_asar_entries(
        &archive,
        &bytes,
        &rel_asar,
        unpacked_root,
        pkg_summary.as_ref(),
        loader_paths_seen,
        state,
    );

    let role = classify_asar_role(&rel_asar);
    state.archives.push(ElectronArchiveInfo {
        path: rel_asar,
        role: role.into(),
        sha256,
        byte_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        unpacked_dir_present: unpacked_root.is_some(),
        header: archive.header,
        package_json: pkg_summary,
        file_count: entries_summary.len(),
        packed_count: counts.packed,
        unpacked_count: counts.unpacked,
        symlink_count: counts.symlinks,
        total_uncompressed_bytes: counts.total_bytes,
        integrity_checked: integrity.checked,
        integrity_valid: integrity.valid,
        integrity_mismatches: integrity.mismatches,
        entries: entries_summary,
    });
    Ok(())
}

fn record_asar_package_metadata(rel_asar: &str, pkg: &PackageSummary, state: &mut AssemblyState) {
    if let Some(spec) = &pkg.electron_spec {
        let clean = clean_semver_spec(spec);
        if !clean.is_empty() {
            state.version_sources.push(VersionObservation {
                source_path: format!("{rel_asar}/package.json"),
                kind: "package-json".into(),
                version: clean.to_string(),
                raw: spec.clone(),
            });
            if state.package_declared_electron.is_none() {
                state.package_declared_electron = Some(clean.to_string());
            }
        }
    }
    if state.app_name.is_none()
        && !has_suffix_ci(rel_asar, ".backup")
        && let Some(name) = &pkg.name
    {
        state.app_name = Some(name.clone());
    }
    if state.app_version.is_none()
        && let Some(ver) = &pkg.version
    {
        state.app_version = Some(ver.clone());
    }
}

fn process_disk_loader(
    root: &Path,
    path: &Path,
    unpack_dir: Option<&Path>,
    loader_paths_seen: &mut BTreeSet<String>,
    state: &mut AssemblyState,
) -> Result<()> {
    let rel = rel_display(root, path);
    if !loader_paths_seen.insert(rel.clone()) {
        return Ok(());
    }
    let bytes = fs::read(path).with_context(|| format!("read loader {}", path.display()))?;
    let dir_rel = path
        .parent()
        .map_or_else(String::new, |p| rel_display(root, p));
    let pkg = state.disk_packages.get(&dir_rel).cloned();
    let pkg_name = pkg.as_ref().and_then(|p| p.name.as_deref());
    let pkg_main = pkg.as_ref().and_then(|p| p.main.as_deref());

    let text = std::str::from_utf8(&bytes).ok();
    let role = if path.parent().is_some_and(has_sibling_asar)
        || text.is_some_and(|t| t.contains(".asar"))
    {
        "asar-loader"
    } else if text.is_some_and(|t| t.contains(".node")) {
        "native-module-loader"
    } else {
        "app-entrypoint"
    };

    let loader = electron_js::inspect_loader(
        &LoaderInput {
            path: &rel,
            location: "filesystem",
            archive: None,
            role,
            package_name: pkg_name,
            package_main: pkg_main,
        },
        &bytes,
    );
    state
        .manifest_items
        .push((rel.clone(), loader.sha256.clone()));

    if let Some(dir) = unpack_dir {
        let dest = dir.join("loaders").join(asar_unpack_subdir(&rel));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &bytes)?;
    }

    if let Some(src) = text {
        let findings = electron_js::analyze_script(&rel, src);
        state.record_script_findings(&rel, findings);
    }
    state.loaders.push(loader);
    Ok(())
}

fn process_unpacked_script(root: &Path, path: &Path, state: &mut AssemblyState) {
    let rel = rel_display(root, path);
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    if let Ok(src) = std::str::from_utf8(&bytes) {
        let findings = electron_js::analyze_script(&rel, src);
        state.record_script_findings(&rel, findings);
    }
}

fn classify_asar_role(rel: &str) -> &'static str {
    let lower = rel.to_ascii_lowercase();
    if has_suffix_ci(&lower, ".backup")
        || has_suffix_ci(&lower, ".bak")
        || has_suffix_ci(&lower, ".orig")
    {
        "backup"
    } else if lower == "app.asar" || lower.ends_with("/app.asar") {
        "app"
    } else if lower == "core.asar" || lower.ends_with("/core.asar") {
        "core"
    } else {
        "archive"
    }
}

fn asar_unpack_subdir(rel: &str) -> PathBuf {
    rel.trim_start_matches("./")
        .trim_start_matches('/')
        .replace(':', "_")
        .into()
}

// ---------------------------------------------------------------------------
// Whole-app state & IR assembly
// ---------------------------------------------------------------------------

struct ApiAccum {
    provenance: ApiProvenance,
    call_count: usize,
    sources: BTreeMap<(String, ScriptRole), usize>,
}

struct IpcAccum {
    directions: BTreeSet<String>,
    resolution: String,
    symbol_names: BTreeSet<String>,
    call_count: usize,
    sources: BTreeMap<(String, ScriptRole), (BTreeSet<String>, usize)>,
}

struct DynamicIpcAccum {
    count: usize,
    sources: BTreeSet<String>,
}

struct AssemblyState {
    root_display: String,
    display_name: String,
    app_name: Option<String>,
    app_version: Option<String>,
    runtime_electron: Option<String>,
    chromium_version: Option<String>,
    package_declared_electron: Option<String>,
    version_sources: Vec<VersionObservation>,
    host_binaries: Vec<ElectronBinaryInfo>,
    build_info: Option<Value>,
    disk_packages: BTreeMap<String, PackageSummary>,
    archives: Vec<ElectronArchiveInfo>,
    loaders: Vec<ElectronLoaderRecord>,
    manifest_items: Vec<(String, String)>,
    apis: BTreeMap<(String, Option<String>), ApiAccum>,
    ipcs: BTreeMap<String, IpcAccum>,
    dynamic_ipcs: BTreeMap<(String, String), DynamicIpcAccum>,
    bridges: BTreeMap<String, BTreeSet<String>>,
}

impl AssemblyState {
    const fn new(root_display: String, display_name: String) -> Self {
        Self {
            root_display,
            display_name,
            app_name: None,
            app_version: None,
            runtime_electron: None,
            chromium_version: None,
            package_declared_electron: None,
            version_sources: Vec::new(),
            host_binaries: Vec::new(),
            build_info: None,
            disk_packages: BTreeMap::new(),
            archives: Vec::new(),
            loaders: Vec::new(),
            manifest_items: Vec::new(),
            apis: BTreeMap::new(),
            ipcs: BTreeMap::new(),
            dynamic_ipcs: BTreeMap::new(),
            bridges: BTreeMap::new(),
        }
    }

    fn record_script_findings(&mut self, source: &str, findings: electron_js::ScriptFindings) {
        let role = findings.role.unwrap_or(ScriptRole::Unknown);
        for hit in findings.api_hits {
            let entry = self
                .apis
                .entry((hit.namespace, hit.member))
                .or_insert_with(|| ApiAccum {
                    provenance: hit.provenance,
                    call_count: 0,
                    sources: BTreeMap::new(),
                });
            if hit.provenance == ApiProvenance::Binding {
                entry.provenance = ApiProvenance::Binding;
            }
            entry.call_count += 1;
            *entry.sources.entry((source.to_string(), role)).or_default() += 1;
        }

        for ipc in findings.ipc_hits {
            let entry = self.ipcs.entry(ipc.channel).or_insert_with(|| IpcAccum {
                directions: BTreeSet::new(),
                resolution: ipc.resolution.clone(),
                symbol_names: BTreeSet::new(),
                call_count: 0,
                sources: BTreeMap::new(),
            });
            if resolution_rank(&ipc.resolution) < resolution_rank(&entry.resolution) {
                entry.resolution = ipc.resolution;
            }
            entry.directions.insert(ipc.direction.clone());
            if let Some(sym) = ipc.symbol_name {
                entry.symbol_names.insert(sym);
            }
            entry.call_count += 1;
            let src_entry = entry
                .sources
                .entry((source.to_string(), role))
                .or_insert_with(|| (BTreeSet::new(), 0));
            src_entry.0.insert(ipc.direction);
            src_entry.1 += 1;
        }

        for dyn_site in findings.dynamic_ipc {
            let entry = self
                .dynamic_ipcs
                .entry((dyn_site.operation, dyn_site.expression))
                .or_insert_with(|| DynamicIpcAccum {
                    count: 0,
                    sources: BTreeSet::new(),
                });
            entry.count += 1;
            entry.sources.insert(source.to_string());
        }

        for key in findings.context_bridges {
            self.bridges
                .entry(key)
                .or_default()
                .insert(source.to_string());
        }
    }

    fn into_database(mut self) -> Database {
        for bin in &self.host_binaries {
            self.manifest_items
                .push((bin.path.clone(), bin.sha256.clone()));
        }
        let composite_sha = composite_manifest_sha(&mut self.manifest_items);
        self.version_sources.sort_by(|a, b| {
            a.source_path
                .cmp(&b.source_path)
                .then_with(|| a.kind.cmp(&b.kind))
        });
        let electron_version = ElectronVersionInfo {
            resolved: self
                .runtime_electron
                .clone()
                .or_else(|| self.package_declared_electron.clone()),
            runtime: self.runtime_electron,
            chromium: self.chromium_version,
            package_declared: self.package_declared_electron,
            sources: self.version_sources,
        };

        self.archives.sort_by(|a, b| a.path.cmp(&b.path));
        self.loaders.sort_by(|a, b| a.path.cmp(&b.path));

        let electron_apis = collect_api_usage(self.apis);
        let ipc_channels = collect_ipc_usage(self.ipcs);
        let dynamic_ipc_sites = collect_dynamic_sites(self.dynamic_ipcs);
        let context_bridges = collect_bridges(self.bridges);
        let deps = collect_dependencies(&electron_version, &self.loaders);
        let total_size = compute_total_size(&self.archives, &self.loaders);
        let machine = self.host_binaries.first().and_then(|b| b.machine.clone());

        let app = ElectronApp {
            root: self.root_display,
            app_name: self.app_name.clone(),
            app_version: self.app_version,
            electron_version,
            host_binaries: self.host_binaries,
            build_info: self.build_info,
            archives: self.archives,
            loaders: self.loaders,
            electron_apis,
            ipc_channels,
            dynamic_ipc_sites,
            context_bridges,
        };

        let (symbols, evidence, claims, proofs) = project_symbols_and_proofs(&app);
        let type_recovery = json!({
            "source": "electron-asar",
            "status": "recovered",
            "electron_version": app.electron_version.resolved,
            "chromium_version": app.electron_version.chromium,
            "archives": app.archives.len(),
            "loaders": app.loaders.len(),
            "apis": app.electron_apis.len(),
            "ipc_channels": app.ipc_channels.len(),
            "dynamic_ipc_sites": app.dynamic_ipc_sites.len(),
            "context_bridges": app.context_bridges.len(),
        });

        Database {
            schema: SCHEMA_VERSION,
            generated: crate::date_today(),
            tool: "rust: electron-asar".into(),
            binary: BinaryInfo {
                file: self.app_name.unwrap_or(self.display_name),
                sha256: Some(composite_sha),
                machine,
                image_size: Some(total_size),
                dependencies: deps,
                ..Default::default()
            },
            symbols,
            type_recovery,
            evidence,
            claims,
            proofs,
            electron: Some(app),
            ..Default::default()
        }
    }
}

fn composite_manifest_sha(items: &mut Vec<(String, String)>) -> String {
    items.sort();
    items.dedup();
    if items.len() == 1 {
        return items[0].1.clone();
    }
    let mut hasher = Sha256::new();
    for (path, sha) in items.iter() {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(sha.as_bytes());
        hasher.update(b"\n");
    }
    crate::hex::lower(&hasher.finalize())
}

fn collect_api_usage(apis: BTreeMap<(String, Option<String>), ApiAccum>) -> Vec<ElectronApiUsage> {
    apis.into_iter()
        .map(|((namespace, member), acc)| ElectronApiUsage {
            api: member
                .as_ref()
                .map_or_else(|| namespace.clone(), |m| format!("{namespace}.{m}")),
            namespace,
            member,
            provenance: acc.provenance,
            call_count: acc.call_count,
            sources: acc
                .sources
                .into_iter()
                .map(|((source, role), count)| ApiSourceRef {
                    source,
                    role,
                    count,
                })
                .collect(),
        })
        .collect()
}

fn collect_ipc_usage(ipcs: BTreeMap<String, IpcAccum>) -> Vec<IpcChannelUsage> {
    ipcs.into_iter()
        .map(|(channel, acc)| IpcChannelUsage {
            channel,
            directions: acc.directions.into_iter().collect(),
            resolution: acc.resolution,
            symbol_names: acc.symbol_names.into_iter().collect(),
            call_count: acc.call_count,
            sources: acc
                .sources
                .into_iter()
                .map(|((source, role), (ops, count))| IpcSourceRef {
                    source,
                    role,
                    operations: ops.into_iter().collect(),
                    count,
                })
                .collect(),
        })
        .collect()
}

fn collect_dynamic_sites(
    dynamic_ipcs: BTreeMap<(String, String), DynamicIpcAccum>,
) -> Vec<DynamicIpcSite> {
    dynamic_ipcs
        .into_iter()
        .map(|((operation, expression), acc)| DynamicIpcSite {
            operation,
            expression,
            count: acc.count,
            sources: acc.sources.into_iter().collect(),
        })
        .collect()
}

fn collect_bridges(bridges: BTreeMap<String, BTreeSet<String>>) -> Vec<ContextBridgeRecord> {
    bridges
        .into_iter()
        .map(|(api_key, sources)| ContextBridgeRecord {
            api_key,
            sources: sources.into_iter().collect(),
        })
        .collect()
}

fn collect_dependencies(
    version: &ElectronVersionInfo,
    loaders: &[ElectronLoaderRecord],
) -> Vec<String> {
    let mut deps = Vec::new();
    if let Some(ev) = &version.resolved {
        deps.push(format!("electron@{ev}"));
    }
    if let Some(cv) = &version.chromium {
        deps.push(format!("chromium@{cv}"));
    }
    for loader in loaders {
        for target in &loader.shape.asar_targets {
            deps.push(target.clone());
        }
    }
    deps.sort();
    deps.dedup();
    deps
}

fn compute_total_size(archives: &[ElectronArchiveInfo], loaders: &[ElectronLoaderRecord]) -> u64 {
    archives
        .iter()
        .map(|a| a.byte_size)
        .sum::<u64>()
        .saturating_add(
            loaders
                .iter()
                .filter(|l| l.location == "filesystem")
                .map(|l| l.byte_len)
                .sum::<u64>(),
        )
}

fn project_symbols_and_proofs(
    app: &ElectronApp,
) -> (Vec<Symbol>, Vec<Evidence>, Vec<Claim>, Vec<Proof>) {
    let mut symbols = Vec::new();
    let mut evidence = Vec::new();
    let mut claims = Vec::new();
    let mut proofs = Vec::new();

    for loader in &app.loaders {
        let id = format!("loader::{}", loader.path);
        symbols.push(electron_symbol(
            id.clone(),
            Kind::Data,
            loader.sha256.clone(),
            loader.byte_len,
            loader.shape.requires.clone(),
        ));
        let ev_id = format!("ev:electron-loader:{}", loader.path);
        let proof_id = format!("proof:electron-loader:{}", loader.path);
        let claim_id = format!("claim:electron-loader:{}", loader.path);
        evidence.push(Evidence {
            id: ev_id.clone(),
            kind: EvidenceKind::Reflection,
            tool: EvidenceTool::Windissect,
            rule_id: "electron.loader-shape".into(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: Some(id),
                ..Default::default()
            },
            observation: EvidenceObservation::Text {
                text: format!(
                    "loader {} ({} bytes, {:?}, sha256 {})",
                    loader.path, loader.byte_len, loader.shape.kind, loader.sha256
                ),
            },
        });
        proofs.push(Proof {
            id: proof_id.clone(),
            rule_id: "electron.loader-sha256".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![ProofObligation {
                name: "verbatim-loader-digest".into(),
                satisfied: true,
                detail: loader.sha256.clone(),
            }],
        });
        claims.push(Claim {
            id: claim_id,
            subject: ClaimSubject::Text {
                category: "electron-loader".into(),
                text: loader.path.clone(),
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec![ev_id],
            proof_id: Some(proof_id),
        });
    }

    for api in &app.electron_apis {
        let sources: Vec<String> = api.sources.iter().map(|s| s.source.clone()).collect();
        symbols.push(electron_symbol(
            format!("electron::{}", api.api),
            Kind::CFunc,
            String::new(),
            0,
            sources,
        ));
    }

    for ipc in &app.ipc_channels {
        symbols.push(electron_symbol(
            format!("ipc::{}", ipc.channel),
            Kind::CFunc,
            String::new(),
            0,
            ipc.directions.clone(),
        ));
    }

    for bridge in &app.context_bridges {
        symbols.push(electron_symbol(
            format!("bridge::{}", bridge.api_key),
            Kind::Data,
            String::new(),
            0,
            bridge.sources.clone(),
        ));
    }

    (symbols, evidence, claims, proofs)
}

fn electron_symbol(
    id: String,
    kind: Kind,
    body_hash: String,
    size: u64,
    imports: Vec<String>,
) -> Symbol {
    Symbol {
        mangled: id.clone(),
        demangled: Some(id.clone()),
        id,
        vaddr: 0,
        rva: 0,
        ordinal: None,
        size: u32::try_from(size).unwrap_or(u32::MAX),
        procedure_size: None,
        is_code: false,
        forwarder: None,
        body_hash,
        exported: true,
        library: false,
        kind,
        coverage: Coverage::Auto,
        provenance: Provenance::Electron,
        confidence: Confidence::Certain,
        sig: Signature::default(),
        callers: vec![],
        calls: vec![],
        imports,
    }
}

fn resolution_rank(res: &str) -> u8 {
    match res {
        "literal" => 0,
        "constant" => 1,
        "wrapper" => 2,
        "whitelist" => 3,
        "enum" => 4,
        _ => 5,
    }
}

fn rel_display(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let s = normalize_path(rel);
    if s.is_empty() {
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(".")
            .to_string()
    } else {
        s
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asar::tests::build_asar;
    use crate::electron_js::{LineEnding, LoaderKind};

    fn write_sample_app(tmp: &Path) -> PathBuf {
        let _ = fs::remove_dir_all(tmp);
        let core_dir = tmp
            .join("modules")
            .join("discord_desktop_core-1")
            .join("discord_desktop_core");
        let res_dir = tmp.join("resources");
        fs::create_dir_all(&core_dir).unwrap();
        fs::create_dir_all(&res_dir).unwrap();

        let mut fake_exe = vec![0u8; 300 * 1024];
        let banner = b"Chrome/152.0.7977.169 Electron/44.10.2\0";
        fake_exe[4096..4096 + banner.len()].copy_from_slice(banner);
        fs::write(tmp.join("SampleApp.exe"), &fake_exe).unwrap();

        fs::write(
            res_dir.join("build_info.json"),
            r#"{"releaseChannel":"stable","version":"1.2.3"}"#,
        )
        .unwrap();
        fs::write(
            core_dir.join("index.js"),
            b"module.exports = require('./core.asar');",
        )
        .unwrap();
        fs::write(
            core_dir.join("package.json"),
            r#"{"name":"sample_core","main":"index.js"}"#,
        )
        .unwrap();

        let core_asar = build_asar(&[
            (
                "package.json",
                br#"{"name":"sample_core","main":"bundle.js","devDependencies":{"electron":"44.9.3"}}"#,
                false,
                true,
            ),
            (
                "bundle.js",
                br#"
                    const { app, BrowserWindow, ipcMain } = require('electron');
                    const GET_VER = "APP_GET_VERSION";
                    ipcMain.handle(GET_VER, () => app.getVersion());
                    ipcMain.on("window:close", () => BrowserWindow.getAllWindows());
                "#
                .as_slice(),
                false,
                true,
            ),
            (
                "preload.js",
                br#"
                    const { contextBridge, ipcRenderer } = require('electron');
                    contextBridge.exposeInMainWorld('AppBridge', {
                        getVersion: () => ipcRenderer.invoke("APP_GET_VERSION"),
                    });
                "#
                .as_slice(),
                false,
                true,
            ),
        ]);
        fs::write(core_dir.join("core.asar"), &core_asar).unwrap();
        core_dir
    }

    #[test]
    fn inspects_multi_asar_app_with_loader_version_apis_and_ipc() {
        let tmp =
            std::env::temp_dir().join(format!("windissect-electron-test-{}", std::process::id()));
        let core_dir = write_sample_app(&tmp);

        let ir_out = tmp.join("ir.json");
        let unpack_dir = tmp.join("unpacked");
        electron_command(&tmp, &ir_out, Some(&unpack_dir)).unwrap();

        let db: Database = serde_json::from_slice(&fs::read(&ir_out).unwrap()).unwrap();
        assert!(crate::verify::run_profile(&db, None));

        let app = db.electron.as_ref().unwrap();
        assert_eq!(app.electron_version.resolved.as_deref(), Some("44.10.2"));
        assert_eq!(app.electron_version.runtime.as_deref(), Some("44.10.2"));
        assert_eq!(
            app.electron_version.chromium.as_deref(),
            Some("152.0.7977.169")
        );
        assert_eq!(
            app.electron_version.package_declared.as_deref(),
            Some("44.9.3")
        );

        let disk_loader = app
            .loaders
            .iter()
            .find(|l| l.location == "filesystem")
            .unwrap();
        assert_eq!(
            disk_loader.exact_text.as_deref(),
            Some("module.exports = require('./core.asar');")
        );
        assert_eq!(disk_loader.formatting.line_ending, LineEnding::None);
        assert_eq!(disk_loader.shape.kind, Some(LoaderKind::AsarPassthrough));
        assert_eq!(disk_loader.shape.asar_targets, vec!["./core.asar"]);

        assert!(app.ipc_channels.iter().any(|c| {
            c.channel == "APP_GET_VERSION"
                && c.directions.contains(&"main-handle".to_string())
                && c.directions.contains(&"renderer-invoke".to_string())
        }));
        assert!(
            app.ipc_channels
                .iter()
                .any(|c| c.channel == "window:close"
                    && c.directions.contains(&"main-on".to_string()))
        );
        assert!(app.context_bridges.iter().any(|b| b.api_key == "AppBridge"));
        assert!(unpack_dir.join("loaders").exists());
        assert!(unpack_dir.join("asars").exists());

        let wrapped_loader =
            b"// wrapper\r\nrequire('electron');\r\nmodule.exports = require('./core.asar');\r\n";
        fs::write(core_dir.join("index.js"), wrapped_loader).unwrap();
        let db2 = inspect_target(&tmp, None).unwrap();
        let report = crate::diff::compare(&db, &db2);
        assert_eq!(report.summary.implementation_changes, 1);

        let _ = fs::remove_dir_all(&tmp);
    }
}
