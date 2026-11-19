//! Electron `.asar` archive parser, integrity verifier, and safe unpacker.
//!
//! An `.asar` file starts with Chromium `Pickle` framing:
//! - `[0..4]`: outer header-size pickle payload length (always `4`)
//! - `[4..8]`: inner header pickle byte size (`header_size`, `>= 8`)
//! - `[8..12]`: inner header pickle payload length
//! - `[12..16]`: JSON string length (`json_size`)
//! - `[16..16 + json_size]`: UTF-8 JSON directory tree (`{"files": ...}`)
//! - `[8 + header_size ..]`: packed file data addressed by `"offset"` + `"size"`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Low-level framing metadata read from an `.asar` Pickle header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsarHeaderInfo {
    pub header_size: u32,
    pub header_payload_size: u32,
    pub json_size: u32,
    pub data_offset: u64,
    pub has_integrity: bool,
}

/// Optional ASAR v2 per-entry SHA-256 integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsarIntegrity {
    pub algorithm: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<String>,
}

/// One file, unpacked file, or symlink recorded in an `.asar` archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsarEntry {
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
    pub integrity: Option<AsarIntegrity>,
}

/// Parsed `.asar` directory table and framing info.
#[derive(Debug, Clone)]
pub struct AsarArchive {
    pub header: AsarHeaderInfo,
    pub entries: Vec<AsarEntry>,
}

/// Result of checking ASAR v2 entry hashes against file bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    pub checked: usize,
    pub valid: usize,
    pub mismatches: Vec<String>,
}

/// Fast 16-byte header check before reading or parsing an entire archive.
#[must_use]
pub const fn is_asar_prefix(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    let u0 = read_u32(bytes, 0);
    let header_size = read_u32(bytes, 4);
    let json_size = read_u32(bytes, 12);
    u0 == 4 && header_size >= 8 && json_size > 0
}

/// Parse an `.asar` archive from raw bytes and validate all packed spans.
pub fn parse(bytes: &[u8]) -> Result<AsarArchive> {
    let (header_size, header_payload_size, json_size, data_offset) = parse_framing(bytes)?;
    let json_end = 16usize + json_size as usize;
    let json_str = std::str::from_utf8(&bytes[16..json_end])
        .context("ASAR directory header is not valid UTF-8")?;
    let root: Value =
        serde_json::from_str(json_str).context("ASAR directory header is not valid JSON")?;

    let mut entries = Vec::new();
    let mut has_integrity = false;
    walk_tree(
        &root,
        "",
        data_offset,
        bytes.len(),
        &mut has_integrity,
        &mut entries,
    )?;

    Ok(AsarArchive {
        header: AsarHeaderInfo {
            header_size,
            header_payload_size,
            json_size,
            data_offset: u64::try_from(data_offset)?,
            has_integrity,
        },
        entries,
    })
}

/// Return the raw byte slice of a packed [`AsarEntry`] from the archive bytes.
#[must_use]
pub fn entry_bytes<'a>(
    archive: &AsarArchive,
    bytes: &'a [u8],
    entry: &AsarEntry,
) -> Option<&'a [u8]> {
    if entry.unpacked || entry.link.is_some() {
        return None;
    }
    let rel = usize::try_from(entry.offset?).ok()?;
    let size = usize::try_from(entry.size).ok()?;
    let data_offset = usize::try_from(archive.header.data_offset).ok()?;
    let start = data_offset.checked_add(rel)?;
    let end = start.checked_add(size)?;
    bytes.get(start..end)
}

/// Find an entry by normalized archive-relative path (for example `"package.json"`).
#[must_use]
pub fn find_entry<'a>(archive: &'a AsarArchive, rel_path: &str) -> Option<&'a AsarEntry> {
    let want = rel_path.trim_start_matches("./").trim_start_matches('/');
    archive.entries.iter().find(|entry| entry.path == want)
}

/// Verify SHA-256 entry hashes recorded in ASAR v2 `integrity` metadata.
#[must_use]
pub fn verify_integrity(
    archive: &AsarArchive,
    bytes: &[u8],
    unpacked_root: Option<&Path>,
) -> IntegrityReport {
    let mut report = IntegrityReport::default();
    for entry in &archive.entries {
        let Some(integrity) = &entry.integrity else {
            continue;
        };
        if !integrity.algorithm.eq_ignore_ascii_case("SHA256") {
            continue;
        }
        let disk_bytes;
        let slice = if entry.unpacked {
            let Some(root) = unpacked_root else {
                continue;
            };
            let Some(safe) = sanitize_rel_path(&entry.path) else {
                report.checked += 1;
                report.mismatches.push(entry.path.clone());
                continue;
            };
            let candidate = root.join(safe);
            let Ok(read) = fs::read(&candidate) else {
                continue;
            };
            disk_bytes = read;
            disk_bytes.as_slice()
        } else if let Some(packed) = entry_bytes(archive, bytes, entry) {
            packed
        } else {
            continue;
        };

        report.checked += 1;
        let actual = crate::hex::lower(&Sha256::digest(slice));
        if actual == integrity.hash.to_ascii_lowercase() {
            report.valid += 1;
        } else {
            report.mismatches.push(entry.path.clone());
        }
    }
    report
}

/// Safely unpack packed (and optionally already-unpacked) entries into `out_dir`.
pub fn unpack(
    archive: &AsarArchive,
    bytes: &[u8],
    out_dir: &Path,
    unpacked_root: Option<&Path>,
) -> Result<usize> {
    fs::create_dir_all(out_dir)?;
    let mut written = 0usize;
    for entry in &archive.entries {
        let Some(rel) = sanitize_rel_path(&entry.path) else {
            bail!("unsafe archive path {:?}", entry.path);
        };
        let dest = out_dir.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        if entry.link.is_some() {
            continue;
        }
        if let Some(data) = entry_bytes(archive, bytes, entry) {
            fs::write(&dest, data)
                .with_context(|| format!("write unpacked entry {}", dest.display()))?;
            written += 1;
        } else if entry.unpacked
            && let Some(root) = unpacked_root
        {
            let src = root.join(&rel);
            if src.is_file() {
                fs::copy(&src, &dest)
                    .with_context(|| format!("copy unpacked sibling {}", dest.display()))?;
                written += 1;
            }
        }
    }
    Ok(written)
}

fn parse_framing(bytes: &[u8]) -> Result<(u32, u32, u32, usize)> {
    if bytes.len() < 16 {
        bail!("file too short ({} bytes) for ASAR header", bytes.len());
    }
    let size_pickle_payload = read_u32(bytes, 0);
    if size_pickle_payload != 4 {
        bail!("invalid ASAR pickle prefix {size_pickle_payload} (expected 4)");
    }
    let header_size = read_u32(bytes, 4);
    let header_payload_size = read_u32(bytes, 8);
    let json_size = read_u32(bytes, 12);
    if header_size < 8 || json_size == 0 {
        bail!("invalid ASAR header dimensions ({header_size}, {json_size})");
    }
    let data_offset = 8usize
        .checked_add(header_size as usize)
        .context("ASAR header offset overflow")?;
    if data_offset > bytes.len() {
        bail!(
            "truncated ASAR header: needs {data_offset} bytes, file has {}",
            bytes.len()
        );
    }
    let json_end = 16usize
        .checked_add(json_size as usize)
        .context("ASAR JSON length overflow")?;
    if json_end > data_offset {
        bail!("corrupt ASAR JSON length {json_size} exceeds data offset {data_offset}");
    }
    Ok((header_size, header_payload_size, json_size, data_offset))
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn walk_tree(
    node: &Value,
    prefix: &str,
    data_offset: usize,
    total_len: usize,
    has_integrity: &mut bool,
    out: &mut Vec<AsarEntry>,
) -> Result<()> {
    let Some(files) = node.get("files").and_then(Value::as_object) else {
        bail!("ASAR directory node `{prefix}` missing `files` object");
    };
    let mut keys: Vec<&String> = files.keys().collect();
    keys.sort();
    for key in keys {
        if !is_safe_segment(key) {
            bail!("unsafe ASAR path component {key:?}");
        }
        let child = &files[key];
        let rel = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}/{key}")
        };
        if child.get("files").is_some() {
            walk_tree(child, &rel, data_offset, total_len, has_integrity, out)?;
            continue;
        }
        if let Some(link) = child.get("link").and_then(Value::as_str) {
            out.push(AsarEntry {
                path: rel,
                size: 0,
                offset: None,
                unpacked: false,
                executable: false,
                link: Some(link.to_string()),
                integrity: None,
            });
            continue;
        }
        let size = child
            .get("size")
            .and_then(Value::as_u64)
            .with_context(|| format!("ASAR entry `{rel}` missing numeric `size`"))?;
        let unpacked = child
            .get("unpacked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let executable = child
            .get("executable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let integrity = parse_integrity(child.get("integrity"));
        if integrity.is_some() {
            *has_integrity = true;
        }

        let offset = if unpacked {
            None
        } else {
            let raw_offset = child
                .get("offset")
                .and_then(Value::as_str)
                .with_context(|| format!("packed ASAR entry `{rel}` missing string `offset`"))?;
            let parsed = raw_offset
                .parse::<u64>()
                .with_context(|| format!("invalid ASAR offset {raw_offset:?} for `{rel}`"))?;
            let abs_start = usize::try_from(parsed)
                .ok()
                .and_then(|rel_off| data_offset.checked_add(rel_off));
            let abs_end = abs_start.and_then(|start| {
                usize::try_from(size)
                    .ok()
                    .and_then(|len| start.checked_add(len))
            });
            let Some(end) = abs_end else {
                bail!("ASAR entry `{rel}` span overflows address space");
            };
            if end > total_len {
                bail!("ASAR entry `{rel}` extends past EOF ({end} > {total_len})");
            }
            Some(parsed)
        };

        out.push(AsarEntry {
            path: rel,
            size,
            offset,
            unpacked,
            executable,
            link: None,
            integrity,
        });
    }
    Ok(())
}

fn parse_integrity(value: Option<&Value>) -> Option<AsarIntegrity> {
    let obj = value?.as_object()?;
    let algorithm = obj.get("algorithm")?.as_str()?.to_string();
    let hash = obj.get("hash")?.as_str()?.to_string();
    let block_size = obj.get("blockSize").and_then(Value::as_u64);
    let blocks = obj
        .get("blocks")
        .and_then(Value::as_array)
        .map_or_default(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        });
    Some(AsarIntegrity {
        algorithm,
        hash,
        block_size,
        blocks,
    })
}

fn is_safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('/')
        && !segment.contains('\\')
        && !segment.contains('\0')
}

fn sanitize_rel_path(rel: &str) -> Option<PathBuf> {
    let mut clean = PathBuf::new();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(part) => {
                let s = part.to_str()?;
                if !is_safe_segment(s) {
                    return None;
                }
                clean.push(s);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!clean.as_os_str().is_empty()).then_some(clean)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::Map;

    pub fn build_asar(files: &[(&str, &[u8], bool, bool)]) -> Vec<u8> {
        let mut root_files = Map::new();
        let mut payload = Vec::new();
        for &(rel, contents, unpacked, with_integrity) in files {
            let parts: Vec<&str> = rel.split('/').collect();
            let mut node = serde_json::Map::new();
            node.insert("size".into(), Value::from(contents.len() as u64));
            if unpacked {
                node.insert("unpacked".into(), Value::from(true));
            } else {
                node.insert("offset".into(), Value::from(payload.len().to_string()));
                payload.extend_from_slice(contents);
            }
            if with_integrity {
                let hash = crate::hex::lower(&Sha256::digest(contents));
                node.insert(
                    "integrity".into(),
                    serde_json::json!({
                        "algorithm": "SHA256",
                        "hash": hash,
                        "blockSize": 4_194_304,
                        "blocks": [hash],
                    }),
                );
            }
            insert_node(&mut root_files, &parts, Value::Object(node));
        }
        let header_json = serde_json::to_vec(&Value::Object({
            let mut root = Map::new();
            root.insert("files".into(), Value::Object(root_files));
            root
        }))
        .unwrap();

        let json_len = u32::try_from(header_json.len()).unwrap();
        let aligned_json_len = (json_len + 3) & !3;
        let inner_payload_len = 4 + aligned_json_len;
        let header_size = 4 + inner_payload_len;

        let mut out = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(&inner_payload_len.to_le_bytes());
        out.extend_from_slice(&json_len.to_le_bytes());
        out.extend_from_slice(&header_json);
        while out.len() < 8 + header_size as usize {
            out.push(0);
        }
        out.extend_from_slice(&payload);
        out
    }

    fn insert_node(dir: &mut Map<String, Value>, parts: &[&str], leaf: Value) {
        if parts.len() == 1 {
            dir.insert(parts[0].to_string(), leaf);
            return;
        }
        let sub = dir
            .entry(parts[0].to_string())
            .or_insert_with(|| {
                Value::Object({
                    let mut m = Map::new();
                    m.insert("files".into(), Value::Object(Map::new()));
                    m
                })
            })
            .as_object_mut()
            .unwrap()
            .get_mut("files")
            .unwrap()
            .as_object_mut()
            .unwrap();
        insert_node(sub, &parts[1..], leaf);
    }

    #[test]
    fn parses_valid_asar_and_verifies_v2_integrity() {
        let bytes = build_asar(&[
            (
                "package.json",
                br#"{"name":"demo","main":"index.js"}"#,
                false,
                true,
            ),
            (
                "sub/index.js",
                b"module.exports = require('electron');",
                false,
                true,
            ),
            ("native/addon.node", b"unpacked", true, false),
        ]);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.entries.len(), 3);
        assert!(archive.header.has_integrity);

        let pkg = find_entry(&archive, "package.json").unwrap();
        assert_eq!(
            entry_bytes(&archive, &bytes, pkg).unwrap(),
            br#"{"name":"demo","main":"index.js"}"#
        );
        let native = find_entry(&archive, "native/addon.node").unwrap();
        assert!(native.unpacked);
        assert!(entry_bytes(&archive, &bytes, native).is_none());

        let report = verify_integrity(&archive, &bytes, None);
        assert_eq!(report.checked, 2);
        assert_eq!(report.valid, 2);
        assert_eq!(report.mismatches, Vec::<String>::new());

        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let broken = verify_integrity(&archive, &tampered, None);
        assert_eq!(broken.checked, 2);
        assert_eq!(broken.valid, 1);
        assert_eq!(broken.mismatches, vec!["sub/index.js"]);
    }

    #[test]
    fn rejects_traversal_and_truncated_entries() {
        let mut raw_header = br#"{"files":{"../evil":{"size":1,"offset":"0"}}}"#.to_vec();
        let json_len = u32::try_from(raw_header.len()).unwrap();
        let aligned = (json_len + 3) & !3;
        while raw_header.len() < aligned as usize {
            raw_header.push(0);
        }
        let mut bad = Vec::new();
        bad.extend_from_slice(&4u32.to_le_bytes());
        bad.extend_from_slice(&(8 + aligned).to_le_bytes());
        bad.extend_from_slice(&(4 + aligned).to_le_bytes());
        bad.extend_from_slice(&json_len.to_le_bytes());
        bad.extend_from_slice(&raw_header);
        bad.push(0x41);
        assert!(parse(&bad).is_err());

        let valid = build_asar(&[("index.js", b"hello", false, false)]);
        let truncated = &valid[..valid.len() - 2];
        assert!(parse(truncated).is_err());
    }
}
