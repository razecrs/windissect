//! Fast binary string discovery with PE-aware file-offset to RVA mapping.

use anyhow::{Context, Result};
use clap::ValueEnum;
use goblin::pe::PE;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum StringEncoding {
    All,
    Ascii,
    Utf16,
}

#[derive(Debug, Clone, Serialize)]
struct StringMatch {
    offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    rva: Option<u32>,
    encoding: &'static str,
    byte_length: usize,
    text: String,
}

struct RawString {
    offset: usize,
    byte_length: usize,
    encoding: &'static str,
    text: String,
}

pub fn search_command(
    binary: &Path,
    query: Option<&str>,
    min_length: usize,
    encoding: StringEncoding,
    case_sensitive: bool,
    json: bool,
    limit: usize,
) -> Result<()> {
    let matches = collect_matches(binary, query, min_length, encoding, case_sensitive, limit)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&matches)?);
        return Ok(());
    }

    print_table(&matches);
    Ok(())
}

pub fn write_inventory(binary: &Path, out: &Path) -> Result<()> {
    let matches = collect_matches(binary, None, 4, StringEncoding::All, false, 0)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, serde_json::to_vec_pretty(&matches)?)?;
    println!("wrote {} strings to {}", matches.len(), out.display());
    Ok(())
}

fn collect_matches(
    binary: &Path,
    query: Option<&str>,
    min_length: usize,
    encoding: StringEncoding,
    case_sensitive: bool,
    limit: usize,
) -> Result<Vec<StringMatch>> {
    anyhow::ensure!(min_length > 0, "--min-length must be greater than zero");
    crate::file_access::ensure_readable(binary)?;
    let bytes = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let pe = PE::parse(&bytes).ok();
    let normalized_query = query.map(|value| {
        if case_sensitive {
            value.to_owned()
        } else {
            value.to_lowercase()
        }
    });

    let mut raw = Vec::new();
    if matches!(encoding, StringEncoding::All | StringEncoding::Ascii) {
        raw.extend(scan_ascii(&bytes, min_length));
    }
    if matches!(encoding, StringEncoding::All | StringEncoding::Utf16) {
        raw.extend(scan_utf16le(&bytes, min_length));
    }
    raw.sort_by_key(|item| (item.offset, item.encoding));

    Ok(raw
        .into_iter()
        .filter(|item| {
            normalized_query.as_ref().is_none_or(|needle| {
                let haystack = if case_sensitive {
                    item.text.clone()
                } else {
                    item.text.to_lowercase()
                };
                haystack.contains(needle)
            })
        })
        .map(|item| StringMatch {
            offset: item.offset,
            rva: pe
                .as_ref()
                .and_then(|image| offset_to_rva(image, item.offset)),
            encoding: item.encoding,
            byte_length: item.byte_length,
            text: item.text,
        })
        .take(if limit == 0 { usize::MAX } else { limit })
        .collect::<Vec<_>>())
}

fn print_table(matches: &[StringMatch]) {
    println!("{:<12} {:<12} {:<8} STRING", "OFFSET", "RVA", "ENCODING");
    for item in matches {
        let rva = item
            .rva
            .map_or_else(|| "—".to_owned(), |value| format!("0x{value:08X}"));
        println!(
            "0x{:08X}  {:<12} {:<8} {}",
            item.offset,
            rva,
            item.encoding,
            escape_for_table(&item.text)
        );
    }
    eprintln!("{} match(es)", matches.len());
}

fn scan_ascii(bytes: &[u8], min_length: usize) -> Vec<RawString> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !is_ascii_printable(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() && is_ascii_printable(bytes[cursor]) {
            cursor += 1;
        }
        if cursor - start >= min_length {
            found.push(RawString {
                offset: start,
                byte_length: cursor - start,
                encoding: "ascii",
                text: String::from_utf8_lossy(&bytes[start..cursor]).into_owned(),
            });
        }
    }
    found
}

fn scan_utf16le(bytes: &[u8], min_length: usize) -> Vec<RawString> {
    let mut found = Vec::new();
    for alignment in 0..=1 {
        let mut cursor = alignment;
        while cursor + 1 < bytes.len() {
            let Some(character) = decode_printable_utf16(bytes, cursor) else {
                cursor += 2;
                continue;
            };
            let start = cursor;
            let mut text = String::new();
            text.push(character);
            cursor += 2;
            while cursor + 1 < bytes.len() {
                let Some(character) = decode_printable_utf16(bytes, cursor) else {
                    break;
                };
                text.push(character);
                cursor += 2;
            }
            if text.chars().count() >= min_length {
                found.push(RawString {
                    offset: start,
                    byte_length: cursor - start,
                    encoding: "utf16le",
                    text,
                });
            }
            cursor += 2;
        }
    }
    found
}

fn is_ascii_printable(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte)
}

fn decode_printable_utf16(bytes: &[u8], offset: usize) -> Option<char> {
    let unit = u16::from_le_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]);
    // Restrict the standalone scanner to common Windows text ranges. This
    // avoids treating arbitrary machine-code words as long CJK strings.
    let common = (0x20..=0x7E).contains(&unit)
        || (0x00A0..=0x024F).contains(&unit)
        || (0x0370..=0x052F).contains(&unit);
    common.then(|| char::from_u32(u32::from(unit))).flatten()
}

fn offset_to_rva(pe: &PE<'_>, offset: usize) -> Option<u32> {
    let offset = u32::try_from(offset).ok()?;
    let headers = pe
        .header
        .optional_header
        .as_ref()
        .map_or(0, |header| header.windows_fields.size_of_headers);
    if offset < headers {
        return Some(offset);
    }
    pe.sections.iter().find_map(|section| {
        let delta = offset.checked_sub(section.pointer_to_raw_data)?;
        (delta < section.size_of_raw_data).then(|| section.virtual_address.saturating_add(delta))
    })
}

fn escape_for_table(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::{scan_ascii, scan_utf16le};

    #[test]
    fn finds_ascii_strings_at_exact_offsets() {
        let found = scan_ascii(b"\0flag{proof}\0xy\0", 4);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, 1);
        assert_eq!(found[0].text, "flag{proof}");
    }

    #[test]
    fn finds_utf16le_strings() {
        let bytes = b"\0f\0l\0a\0g\0\0";
        let found = scan_utf16le(bytes, 4);
        assert!(
            found
                .iter()
                .any(|item| item.offset == 1 && item.text == "flag")
        );
    }
}
