//! Emit a C header of `WinRT` interface IIDs and ABI vtable slots.
//!
//! Input is one or more IR databases produced by `windissect winmd`. Each
//! requested interface must exist in that evidence with a `GuidAttribute` IID
//! and a slot for every method, otherwise nothing is written: a consumer never
//! compiles against a guessed IID or slot.
//!
//! Output, per interface `Ns.IFoo` (generic ``IFoo`1`` becomes `IFoo_1`):
//!   `WINRT_IID_IFoo`            -> `const GUID *` (compound literal)
//!   `WINRT_SLOT_IFoo_<method>`  -> vtable index, `IInspectable` base included
//! and per enum `Ns.Foo`:
//!   `WINRT_ENUM_Foo_<value>`    -> the enum constant
//! Generic definitions carry no usable IID (each instantiation has its own),
//! so only their slots are emitted.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::model::Database;

struct Source {
    file: String,
    sha256: String,
}

struct Interface<'a> {
    qualified: String,
    ident: String,
    iid: Option<String>,
    members: Vec<(String, u32)>,
    values: Vec<(String, i64)>,
    source: &'a Source,
}

fn c_ident(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn guid_initializer(iid: &str) -> Result<String> {
    let hex: String = iid.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 32 || iid.len() != 36 {
        bail!("malformed IID {iid}");
    }
    let part = |range: std::ops::Range<usize>| &hex[range];
    let mut tail = String::new();
    for i in 0..8 {
        if i > 0 {
            tail.push_str(", ");
        }
        let _ = write!(tail, "0x{}", part(16 + i * 2..18 + i * 2));
    }
    Ok(format!(
        "{{0x{}, 0x{}, 0x{}, {{{tail}}}}}",
        part(0..8),
        part(8..12),
        part(12..16)
    ))
}

fn enum_from<'a>(record: &Value, source: &'a Source) -> Result<Interface<'a>> {
    let qualified = record["qualified_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let mut values = Vec::new();
    for entry in record["values"].as_array().into_iter().flatten() {
        let (Some(name), Some(value)) = (entry["name"].as_str(), entry["value"].as_i64()) else {
            bail!("{qualified} has a malformed enum value in {}", source.file);
        };
        values.push((c_ident(name), value));
    }
    if values.is_empty() {
        bail!(
            "{qualified} has no enum values in {} (re-extract with this windissect)",
            source.file
        );
    }
    Ok(Interface {
        ident: c_ident(record["name"].as_str().unwrap_or_default()),
        qualified,
        iid: None,
        members: Vec::new(),
        values,
        source,
    })
}

fn interface_from<'a>(record: &Value, source: &'a Source) -> Result<Interface<'a>> {
    if record["category"].as_str() == Some("enum") {
        return enum_from(record, source);
    }
    let qualified = record["qualified_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let name = record["name"].as_str().unwrap_or_default();
    let generic = name.contains('`');
    // A generic definition's GUID is the pinterface seed, never a QI-able IID.
    let iid = if generic {
        None
    } else {
        record["iid"].as_str().map(str::to_string)
    };
    if iid.is_none() && !generic {
        bail!("{qualified} has no GuidAttribute IID in {}", source.file);
    }

    let mut seen: HashMap<String, u32> = HashMap::new();
    let mut members = Vec::new();
    for member in record["members"].as_array().into_iter().flatten() {
        let method = member["name"].as_str().unwrap_or_default();
        let Some(slot) = member["slot"].as_u64().and_then(|s| u32::try_from(s).ok()) else {
            bail!("{qualified}.{method} has no vtable slot in {}", source.file);
        };
        // Overloads share a metadata name; later ones get _2, _3, ... in slot order.
        let count = seen.entry(method.to_string()).or_insert(0);
        *count += 1;
        let ident = if *count == 1 {
            c_ident(method)
        } else {
            format!("{}_{}", c_ident(method), count)
        };
        members.push((ident, slot));
    }

    Ok(Interface {
        qualified,
        ident: c_ident(name),
        iid,
        members,
        values: Vec::new(),
        source,
    })
}

/// Write `<name>_winrt.h` into `out_dir` for the `wanted` qualified interfaces.
pub fn emit_winrt(dbs: &[Database], wanted: &[String], name: &str, out_dir: &Path) -> Result<()> {
    if wanted.is_empty() {
        bail!("emit-winrt needs at least one --want interface");
    }
    let sources: Vec<Source> = dbs
        .iter()
        .map(|db| Source {
            file: db.binary.file.clone(),
            sha256: db.binary.sha256.clone().unwrap_or_default(),
        })
        .collect();

    let mut index: HashMap<&str, (&Value, &Source)> = HashMap::new();
    for (db, source) in dbs.iter().zip(&sources) {
        for record in &db.classes {
            if !matches!(record["category"].as_str(), Some("interface" | "enum")) {
                continue;
            }
            if let Some(q) = record["qualified_name"].as_str() {
                index.insert(q, (record, source));
            }
        }
    }

    let mut chosen = Vec::new();
    let mut idents: BTreeMap<String, String> = BTreeMap::new();
    for want in wanted {
        let Some((record, source)) = index.get(want.as_str()) else {
            bail!("{want} is not an interface or enum in the supplied winmd evidence");
        };
        let iface = interface_from(record, source)?;
        if let Some(previous) = idents.insert(iface.ident.clone(), iface.qualified.clone()) {
            if previous != iface.qualified {
                bail!(
                    "{previous} and {} both map to {}",
                    iface.qualified,
                    iface.ident
                );
            }
            continue;
        }
        chosen.push(iface);
    }

    let ident = c_ident(name);
    let guard = format!("WINRT_{}_H", ident.to_ascii_uppercase());
    let mut h = String::new();
    let _ = writeln!(h, "/* Generated by windissect emit-winrt. Do not edit.");
    let _ = writeln!(
        h,
        "   WinRT IIDs and ABI vtable slots, from winmd evidence:"
    );
    for source in &sources {
        let _ = writeln!(h, "     {} sha256 {}", source.file, source.sha256);
    }
    let _ = writeln!(
        h,
        "*/\n#ifndef {guard}\n#define {guard}\n\n#include <guiddef.h>\n"
    );
    for iface in &chosen {
        let _ = writeln!(h, "/* {} ({}) */", iface.qualified, iface.source.file);
        if let Some(iid) = &iface.iid {
            let init = guid_initializer(iid).with_context(|| iface.qualified.clone())?;
            let _ = writeln!(h, "#define WINRT_IID_{} (&(const GUID){init})", iface.ident);
        }
        for (method, slot) in &iface.members {
            let _ = writeln!(h, "#define WINRT_SLOT_{}_{method} {slot}", iface.ident);
        }
        for (value_name, value) in &iface.values {
            let _ = writeln!(
                h,
                "#define WINRT_ENUM_{}_{value_name} ({value})",
                iface.ident
            );
        }
        h.push('\n');
    }
    let _ = writeln!(h, "#endif");

    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let path = out_dir.join(format!("{ident}_winrt.h"));
    crate::diff::atomic_write(&path, h.as_bytes())?;
    println!(
        "wrote {} types ({} slots, {} enum values) -> {}",
        chosen.len(),
        chosen.iter().map(|i| i.members.len()).sum::<usize>(),
        chosen.iter().map(|i| i.values.len()).sum::<usize>(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn db_with(classes: Vec<Value>) -> Database {
        let mut db = Database::default();
        db.binary.file = "Sample.winmd".into();
        db.binary.sha256 = Some("ab".repeat(32));
        db.classes = classes;
        db
    }

    fn iface(name: &str, iid: Option<&str>, members: &Value) -> Value {
        let mut record = json!({
            "namespace": "Sample",
            "name": name,
            "qualified_name": format!("Sample.{name}"),
            "category": "interface",
            "members": members,
        });
        if let Some(iid) = iid {
            record["iid"] = json!(iid);
        }
        record
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "windissect-emit-winrt-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn emits_iids_slots_and_overload_suffixes() {
        let db = db_with(vec![
            iface(
                "IThing",
                Some("676d0be9-b65c-41c6-ba40-58cf87f201c1"),
                &json!([
                    {"name": "get_Size", "slot": 6},
                    {"name": "Make", "slot": 7},
                    {"name": "Make", "slot": 8}
                ]),
            ),
            iface(
                "IList`1",
                Some("913337e9-11a1-4345-a3a2-4e7f956e222d"),
                &json!([{"name": "Append", "slot": 13}]),
            ),
            json!({
                "name": "Side", "qualified_name": "Sample.Side", "category": "enum",
                "values": [{"name": "Left", "value": 0}, {"name": "Bottom", "value": -2}]
            }),
            json!({"name": "Empty", "qualified_name": "Sample.Empty", "category": "enum", "values": []}),
        ]);
        let out = temp_dir("ok");
        let dbs = [db];
        let wanted = [
            "Sample.IThing".into(),
            "Sample.IList`1".into(),
            "Sample.Side".into(),
        ];
        emit_winrt(&dbs, &wanted, "sample", &out).unwrap();
        let h = std::fs::read_to_string(out.join("sample_winrt.h")).unwrap();
        assert!(h.contains(
            "#define WINRT_IID_IThing (&(const GUID){0x676d0be9, 0xb65c, 0x41c6, \
             {0xba, 0x40, 0x58, 0xcf, 0x87, 0xf2, 0x01, 0xc1}})"
        ));
        assert!(h.contains("#define WINRT_SLOT_IThing_get_Size 6"));
        assert!(h.contains("#define WINRT_SLOT_IThing_Make 7"));
        assert!(h.contains("#define WINRT_SLOT_IThing_Make_2 8"));
        assert!(h.contains("#define WINRT_SLOT_IList_1_Append 13"));
        assert!(!h.contains("WINRT_IID_IList_1"));
        assert!(h.contains("#define WINRT_ENUM_Side_Left (0)"));
        assert!(h.contains("#define WINRT_ENUM_Side_Bottom (-2)"));
        assert!(emit_winrt(&dbs, &["Sample.Empty".into()], "empty", &out).is_err());
        assert!(h.contains("Sample.winmd sha256 abab"));
    }

    #[test]
    fn refuses_missing_interfaces_iids_and_slots() {
        let db = db_with(vec![
            iface("INoIid", None, &json!([])),
            iface(
                "INoSlot",
                Some("676d0be9-b65c-41c6-ba40-58cf87f201c1"),
                &json!([{"name": "Run"}]),
            ),
        ]);
        let out = temp_dir("bad");
        let dbs = [db];
        assert!(emit_winrt(&dbs, &["Sample.IMissing".into()], "s", &out).is_err());
        assert!(emit_winrt(&dbs, &["Sample.INoIid".into()], "s", &out).is_err());
        assert!(emit_winrt(&dbs, &["Sample.INoSlot".into()], "s", &out).is_err());
        assert!(!out.join("s_winrt.h").exists());
    }
}
