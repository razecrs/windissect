//! Exact-build, opt-in semantic runtime probing.

use crate::model::Database;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeManifest {
    pub schema: u32,
    pub binary_sha256: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub operations: Vec<ProbeOperation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProbeOperation {
    ReadRva {
        id: String,
        rva: u32,
        size: u32,
    },
    CallNoArgs {
        id: String,
        symbol_id: String,
        rva: u32,
        acknowledge_side_effects: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub schema: u32,
    pub binary_sha256: String,
    pub observations: Vec<ProbeObservation>,
}

#[cfg(test)]
pub const fn runtime_supported() -> bool {
    cfg!(windows)
}

pub fn write_static_only(db: &Database, out: &Path) -> Result<()> {
    let mut observations = vec![ProbeObservation {
        id: "runtime-capability".into(),
        status: "static-only".into(),
        detail: "runtime calls require an explicit exact-build probe manifest".into(),
    }];
    observations.extend(
        db.symbols
            .iter()
            .filter(|symbol| symbol.is_code && symbol.sig.class.is_none())
            .filter(|symbol| symbol.sig.params.is_empty())
            .filter(|symbol| db.symbol_is_verified_callable(&symbol.id))
            .map(|symbol| ProbeObservation {
                id: format!("withheld:{:08X}:{}", symbol.rva, symbol.id),
                status: "withheld".into(),
                detail: "addressability and ABI are verified, but host-context preconditions and side effects are not"
                    .into(),
            }),
    );
    let result = ProbeResult {
        schema: 1,
        binary_sha256: db.binary.sha256.clone().unwrap_or_default(),
        observations,
    };
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(&result)?)
}

pub fn import_result(db: &mut Database, path: &Path) -> Result<usize> {
    let result: ProbeResult = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    let mut imported = 0;
    for observation in result.observations {
        if observation.status != "returned" {
            continue;
        }
        let digest = Sha256::digest(observation.id.as_bytes());
        let suffix = &crate::hex::lower(&digest)[..16];
        let evidence_id = format!("ev:runtime-return:{suffix}");
        let proof_id = format!("proof:runtime-return:{suffix}");
        let claim_id = format!("claim:runtime-return:{suffix}");
        if db.claims.iter().any(|claim| claim.id == claim_id) {
            continue;
        }
        let text = format!("{} returned {}", observation.id, observation.detail);
        db.evidence.push(crate::model::Evidence {
            id: evidence_id.clone(),
            kind: crate::model::EvidenceKind::Dataflow,
            tool: crate::model::EvidenceTool::Windissect,
            rule_id: "runtime.exact-build-return".into(),
            rule_version: 1,
            location: crate::model::EvidenceLocation::default(),
            observation: crate::model::EvidenceObservation::Text { text: text.clone() },
        });
        db.proofs.push(crate::model::Proof {
            id: proof_id.clone(),
            rule_id: "runtime.exact-build-return".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![crate::model::ProofObligation {
                name: "exact-binary-hash".into(),
                satisfied: true,
                detail: result.binary_sha256.clone(),
            }],
        });
        db.claims.push(crate::model::Claim {
            id: claim_id,
            subject: crate::model::ClaimSubject::Text {
                category: "runtime-return".into(),
                text,
            },
            status: crate::model::ClaimStatus::Derived,
            usability: crate::model::Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id),
        });
        imported += 1;
    }
    Ok(imported)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeObservation {
    pub id: String,
    pub status: String,
    pub detail: String,
}

const fn default_timeout() -> u64 {
    10_000
}

pub fn load_and_validate(db: &Database, binary: &Path, path: &Path) -> Result<ProbeManifest> {
    ensure!(
        binary
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dll")),
        "runtime semantic probing is DLL-only; EXE and SYS targets are static-only"
    );
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: ProbeManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing probe manifest {}", path.display()))?;
    ensure!(
        manifest.schema == 1,
        "unsupported probe manifest schema {}",
        manifest.schema
    );
    let expected = db
        .binary
        .sha256
        .as_deref()
        .context("IR has no binary SHA-256")?;
    ensure!(
        manifest.binary_sha256.eq_ignore_ascii_case(expected),
        "probe manifest hash mismatch: IR {expected}, manifest {}",
        manifest.binary_sha256
    );
    ensure!(
        !manifest.operations.is_empty(),
        "probe manifest has no operations"
    );
    ensure!(
        manifest.timeout_ms > 0 && manifest.timeout_ms <= 30_000,
        "probe timeout must be in 1..=30000 ms"
    );
    let image_size = db.binary.image_size.unwrap_or(0);
    for operation in &manifest.operations {
        match operation {
            ProbeOperation::ReadRva { id, rva, size } => {
                ensure!(!id.is_empty(), "probe operation has an empty id");
                ensure!(
                    *size > 0 && *size <= 4096,
                    "probe read {id} size must be in 1..=4096"
                );
                ensure!(
                    u64::from(*rva) + u64::from(*size) <= image_size,
                    "probe read {id} exceeds image bounds"
                );
            }
            ProbeOperation::CallNoArgs {
                id,
                symbol_id,
                rva,
                acknowledge_side_effects,
            } => {
                ensure!(
                    *acknowledge_side_effects,
                    "probe call {id} must acknowledge side effects"
                );
                let symbol = db
                    .symbols
                    .iter()
                    .find(|symbol| symbol.id == *symbol_id)
                    .with_context(|| format!("probe call {id} names unknown symbol {symbol_id}"))?;
                ensure!(
                    symbol.rva == *rva,
                    "probe call {id} RVA does not match the exact-build IR"
                );
                ensure!(
                    db.symbol_is_verified_callable(symbol_id),
                    "probe call {id} is not proof-gated callable"
                );
                ensure!(
                    symbol.sig.params.is_empty(),
                    "probe call {id} is not a zero-argument function"
                );
                ensure!(
                    symbol.sig.class.is_none() || symbol.sig.storage.as_deref() == Some("static"),
                    "probe call {id} requires a this pointer"
                );
            }
        }
    }
    Ok(manifest)
}

pub fn run_isolated(binary: &Path, manifest: &Path, out: &Path, timeout_ms: u64) -> Result<()> {
    let source: ProbeManifest = serde_json::from_slice(&std::fs::read(manifest)?)?;
    let executable = std::env::current_exe()?;
    let mut observations = Vec::new();
    let mut failed = 0usize;
    let scratch = std::env::temp_dir().join(format!(
        "windissect-probe-{}-{}",
        std::process::id(),
        crate::hex::lower(&Sha256::digest(manifest.as_os_str().as_encoded_bytes()))[..12]
            .to_string()
    ));
    std::fs::create_dir_all(&scratch)?;

    for (index, operation) in source.operations.iter().enumerate() {
        let operation_value = serde_json::to_value(operation)?;
        let operation_id = operation_value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .context("probe operation has no string id")?
            .to_owned();
        let operation_manifest = scratch.join(format!("{index:03}-manifest.json"));
        let operation_out = scratch.join(format!("{index:03}-result.json"));
        let single = serde_json::json!({
            "schema": source.schema,
            "binary_sha256": &source.binary_sha256,
            "timeout_ms": source.timeout_ms,
            "operations": [operation_value],
        });
        crate::diff::atomic_write(&operation_manifest, &serde_json::to_vec(&single)?)?;

        let mut command = std::process::Command::new(&executable);
        command
            .arg("semantic-probe-helper")
            .arg("--binary")
            .arg(binary)
            .arg("--manifest")
            .arg(&operation_manifest)
            .arg("--out")
            .arg(&operation_out);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn()?;
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if start.elapsed() > std::time::Duration::from_millis(timeout_ms) {
                child.kill()?;
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        if status.is_some_and(|value| value.success()) {
            let result: ProbeResult = serde_json::from_slice(&std::fs::read(&operation_out)?)?;
            observations.extend(result.observations);
        } else {
            failed += 1;
            let (status, detail) = match status {
                Some(value) => ("crashed", format!("isolated helper failed with {value}")),
                None => (
                    "timed-out",
                    format!("isolated helper exceeded {timeout_ms} ms"),
                ),
            };
            eprintln!("semantic probe {operation_id}: {detail}");
            observations.push(ProbeObservation {
                id: operation_id,
                status: status.into(),
                detail,
            });
        }
    }

    let result = ProbeResult {
        schema: 1,
        binary_sha256: source.binary_sha256,
        observations,
    };
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(&result)?)?;
    let _ = std::fs::remove_dir_all(&scratch);
    if failed > 0 {
        eprintln!(
            "semantic probe: {failed}/{} operations failed safely in isolated helpers",
            source.operations.len()
        );
    }
    Ok(())
}

pub fn helper(binary: &Path, manifest_path: &Path, out: &Path) -> Result<()> {
    let manifest: ProbeManifest = serde_json::from_slice(&std::fs::read(manifest_path)?)?;
    let actual = crate::hex::upper(&Sha256::digest(&std::fs::read(binary)?));
    ensure!(
        actual.eq_ignore_ascii_case(&manifest.binary_sha256),
        "probe helper binary hash mismatch"
    );
    let observations = platform_probe(binary, &manifest)?;
    let result = ProbeResult {
        schema: 1,
        binary_sha256: manifest.binary_sha256,
        observations,
    };
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(&result)?)
}

#[cfg(windows)]
fn platform_probe(binary: &Path, manifest: &ProbeManifest) -> Result<Vec<ProbeObservation>> {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }
    let wide: Vec<u16> = OsStr::new(binary.as_os_str())
        .encode_wide()
        .chain(Some(0))
        .collect();
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    ensure!(
        !module.is_null(),
        "LoadLibraryW failed for {}",
        binary.display()
    );
    let mut observations = Vec::new();
    for operation in &manifest.operations {
        match operation {
            ProbeOperation::ReadRva { id, rva, size } => {
                let address_offset = usize::try_from(*rva).context("RVA does not fit usize")?;
                let byte_count = usize::try_from(*size).context("probe size does not fit usize")?;
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        (module as *const u8).add(address_offset),
                        byte_count,
                    )
                };
                observations.push(ProbeObservation {
                    id: id.clone(),
                    status: "observed".into(),
                    detail: crate::hex::upper(bytes),
                });
            }
            ProbeOperation::CallNoArgs { id, rva, .. } => {
                let address_offset = usize::try_from(*rva).context("RVA does not fit usize")?;
                let address = unsafe { (module as *const u8).add(address_offset) };
                let function: unsafe extern "system" fn() -> usize =
                    unsafe { std::mem::transmute(address) };
                let value = unsafe { function() };
                observations.push(ProbeObservation {
                    id: id.clone(),
                    status: "returned".into(),
                    detail: format!("0x{value:X}"),
                });
            }
        }
    }
    unsafe { FreeLibrary(module) };
    Ok(observations)
}

#[cfg(not(windows))]
fn platform_probe(_binary: &Path, _manifest: &ProbeManifest) -> Result<Vec<ProbeObservation>> {
    anyhow::bail!("semantic runtime probing is Windows-only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BinaryInfo;

    #[test]
    fn sys_probe_is_rejected() {
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("00".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = load_and_validate(&db, Path::new("driver.sys"), Path::new("missing.json"));
        assert!(result.unwrap_err().to_string().contains("DLL-only"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_host_uses_static_fallback() {
        assert!(!runtime_supported());
    }

    #[cfg(windows)]
    #[test]
    fn windows_host_supports_runtime_probe() {
        assert!(runtime_supported());
    }

    #[test]
    fn static_refinement_records_explicit_probe_requirement() {
        let path = std::env::temp_dir().join(format!(
            "windissect-static-probe-{}.json",
            std::process::id()
        ));
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("CC".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        write_static_only(&db, &path).unwrap();
        let result: ProbeResult = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].status, "static-only");
        assert!(result.observations[0].detail.contains("explicit"));
    }

    #[test]
    fn imported_return_is_a_proof_gated_claim() {
        let path = std::env::temp_dir().join(format!(
            "windissect-probe-import-{}.json",
            std::process::id()
        ));
        let result = ProbeResult {
            schema: 1,
            binary_sha256: "AA".repeat(32),
            observations: vec![ProbeObservation {
                id: "auto:test".into(),
                status: "returned".into(),
                detail: "0x2A".into(),
            }],
        };
        std::fs::write(&path, serde_json::to_vec(&result).unwrap()).unwrap();
        let expected_hash = result.binary_sha256;
        let mut db = Database {
            binary: BinaryInfo {
                sha256: Some(expected_hash),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(import_result(&mut db, &path).unwrap(), 1);
        assert_eq!(db.proven_claim_ids().len(), 1);
        assert_eq!(import_result(&mut db, &path).unwrap(), 0);
        std::fs::remove_file(path).unwrap();
    }
}
