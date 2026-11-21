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
//! per delegate `Ns.FooHandler` (an `IUnknown` with `Invoke` at slot 3):
//!   `WINRT_IID_FooHandler`, `WINRT_SLOT_FooHandler_Invoke`
//! per enum `Ns.Foo`:
//!   `WINRT_ENUM_Foo_<value>`    -> the enum constant
//! and per struct `Ns.Foo`:
//!   `winrt_Foo`                 -> a C typedef with the metadata's fields in
//!                                  declaration order (`WinRT` structs are
//!                                  sequential with natural alignment); a field
//!                                  of struct type needs that struct wanted too,
//!                                  earlier in the list.
//! Generic definitions carry no usable IID (each instantiation has its own),
//! so only their slots are emitted. A wanted instantiation such as
//! ``Windows.Foundation.IReference`1<Double>`` gets its IID computed the way
//! the `WinRT` runtime does: a SHA-1 name-based UUID (version 5) over the
//! parameterized-interface namespace and the signature
//! `pinterface({definition GUID};f8)`, emitted as `WINRT_IID_IReference_1_Double`
//! together with the definition's slots.

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
    /// Struct fields as (C type, field name), in declaration order.
    fields: Vec<(String, String)>,
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
        fields: Vec::new(),
        source,
    })
}

/// C spelling of a field type: a primitive, an enum's storage type, or a
/// struct already emitted in this header.
fn c_field_type(
    ty: &str,
    index: &HashMap<&str, (&Value, &Source)>,
    emitted: &HashMap<String, String>,
) -> Option<String> {
    let primitive = match ty {
        "Bool" | "U8" => "uint8_t",
        "I8" => "int8_t",
        "I16" => "int16_t",
        "U16" | "Char" => "uint16_t",
        "I32" => "int32_t",
        "U32" => "uint32_t",
        "I64" => "int64_t",
        "U64" => "uint64_t",
        "F32" => "float",
        "F64" => "double",
        "String" => "void *", /* HSTRING */
        _ => "",
    };
    if !primitive.is_empty() {
        return Some(primitive.to_string());
    }
    if let Some(c_name) = emitted.get(ty) {
        return Some(c_name.clone());
    }
    let (record, _) = index.get(ty)?;
    if record["category"].as_str() == Some("enum") {
        let storage = record["underlying"].as_str().unwrap_or("I32");
        return c_field_type(storage, index, emitted);
    }
    None
}

fn struct_from<'a>(
    record: &Value,
    source: &'a Source,
    index: &HashMap<&str, (&Value, &Source)>,
    emitted: &HashMap<String, String>,
) -> Result<Interface<'a>> {
    let qualified = record["qualified_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let Some(raw_fields) = record["fields"].as_array() else {
        bail!(
            "{qualified} has no struct fields in {} (re-extract with this windissect)",
            source.file
        );
    };
    let mut fields = Vec::new();
    for field in raw_fields {
        let (Some(name), Some(ty)) = (field["name"].as_str(), field["type"].as_str()) else {
            bail!("{qualified} has a malformed field in {}", source.file);
        };
        let Some(c_type) = c_field_type(ty, index, emitted) else {
            bail!(
                "{qualified}.{name} has type {ty}, which is not a primitive, an enum, or a struct wanted earlier"
            );
        };
        fields.push((c_type, c_ident(name)));
    }
    if fields.is_empty() {
        bail!("{qualified} has no fields in {}", source.file);
    }
    Ok(Interface {
        ident: c_ident(record["name"].as_str().unwrap_or_default()),
        qualified,
        iid: None,
        members: Vec::new(),
        values: Vec::new(),
        fields,
        source,
    })
}

/// SHA-1 (FIPS 180-4). Only used to derive parameterized `WinRT` IIDs.
// The single-letter names follow the standard's notation (a..e, f, k, w).
#[allow(clippy::many_single_char_names)]
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Signature element of a primitive generic argument (`WinRT` type system).
fn primitive_signature(arg: &str) -> Option<&'static str> {
    Some(match arg {
        "Boolean" => "b1",
        "Char16" => "c2",
        "Int8" => "i1",
        "UInt8" => "u1",
        "Int16" => "i2",
        "UInt16" => "u2",
        "Int32" => "i4",
        "UInt32" => "u4",
        "Int64" => "i8",
        "UInt64" => "u8",
        "Single" => "f4",
        "Double" => "f8",
        "String" => "string",
        "Guid" => "g16",
        "Object" => "cinterface(IInspectable)",
        _ => return None,
    })
}

/// Canonical IID text of a parameterized interface instance.
fn pinterface_iid(definition_iid: &str, args: &[&str]) -> Result<String> {
    // Namespace of every pinterface IID: 11f47ad5-7b73-42c0-abae-878b1e16adee.
    const NAMESPACE: [u8; 16] = [
        0x11, 0xf4, 0x7a, 0xd5, 0x7b, 0x73, 0x42, 0xc0, 0xab, 0xae, 0x87, 0x8b, 0x1e, 0x16, 0xad,
        0xee,
    ];
    let mut signature = format!("pinterface({{{}}}", definition_iid.to_ascii_lowercase());
    for arg in args {
        let Some(element) = primitive_signature(arg) else {
            bail!("generic argument {arg} is not a primitive emit-winrt can sign");
        };
        signature.push(';');
        signature.push_str(element);
    }
    signature.push(')');
    let mut input = NAMESPACE.to_vec();
    input.extend_from_slice(signature.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&sha1(&input)[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

/// ``Ns.IFoo`1<Double>`` -> the definition ``Ns.IFoo`1`` and its arguments.
fn split_instance(want: &str) -> Option<(&str, Vec<&str>)> {
    let open = want.find('<')?;
    let inner = want.strip_suffix('>')?.get(open + 1..)?;
    Some((&want[..open], inner.split(',').map(str::trim).collect()))
}

fn instance_from<'a>(
    record: &Value,
    source: &'a Source,
    want: &str,
    args: &[&str],
) -> Result<Interface<'a>> {
    let mut iface = interface_from(record, source)?;
    let Some(seed) = record["iid"].as_str() else {
        bail!(
            "{want}: the generic definition has no GuidAttribute in {}",
            source.file
        );
    };
    iface.iid = Some(pinterface_iid(seed, args)?);
    iface.ident = format!(
        "{}_{}",
        iface.ident,
        args.iter()
            .map(|a| c_ident(a))
            .collect::<Vec<_>>()
            .join("_")
    );
    iface.qualified = want.to_string();
    Ok(iface)
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

    let delegate = record["category"].as_str() == Some("delegate");
    let mut seen: HashMap<String, u32> = HashMap::new();
    let mut members = Vec::new();
    for member in record["members"].as_array().into_iter().flatten() {
        let method = member["name"].as_str().unwrap_or_default();
        // A delegate's metadata constructor is not part of its ABI vtable.
        if delegate && method == ".ctor" {
            continue;
        }
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
        fields: Vec::new(),
        source,
    })
}

/// Write `<name>_winrt.h` into `out_dir` for the `wanted` qualified interfaces.
// Emits the header top to bottom in one pass; splitting it would only
// thread the output buffer through helpers.
#[allow(clippy::too_many_lines)]
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
            if !matches!(
                record["category"].as_str(),
                Some("interface" | "delegate" | "enum" | "struct")
            ) {
                continue;
            }
            if let Some(q) = record["qualified_name"].as_str() {
                index.insert(q, (record, source));
            }
        }
    }

    let mut chosen = Vec::new();
    let mut idents: BTreeMap<String, String> = BTreeMap::new();
    let mut emitted_structs: HashMap<String, String> = HashMap::new();
    for want in wanted {
        // A generic instantiation is looked up by its definition.
        let instance = split_instance(want).and_then(|(definition, args)| {
            index
                .get(definition)
                .map(|(record, source)| (*record, *source, args))
        });
        let lookup = split_instance(want).map_or(want.as_str(), |(definition, _)| definition);
        let Some((record, source)) = index.get(lookup) else {
            bail!(
                "{want} is not an interface, delegate, enum or struct in the supplied winmd evidence"
            );
        };
        let iface = if let Some((args_record, args_source, args)) = instance.as_ref() {
            instance_from(args_record, args_source, want, args)?
        } else if record["category"].as_str() == Some("struct") {
            let s = struct_from(record, source, &index, &emitted_structs)?;
            emitted_structs.insert(s.qualified.clone(), format!("winrt_{}", s.ident));
            s
        } else {
            interface_from(record, source)?
        };
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
        "*/\n#ifndef {guard}\n#define {guard}\n\n#include <guiddef.h>\n#include <stdint.h>\n"
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
        if !iface.fields.is_empty() {
            let _ = writeln!(h, "typedef struct winrt_{} {{", iface.ident);
            for (c_type, field) in &iface.fields {
                let _ = writeln!(h, "    {c_type} {field};");
            }
            let _ = writeln!(h, "}} winrt_{};", iface.ident);
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
    fn emits_delegate_iid_and_invoke_slot() {
        let mut handler = iface(
            "ThingHandler",
            Some("1115b13c-25d2-480b-89dc-eb3dcbd6b7fa"),
            &json!([
                {"name": ".ctor", "params": ["object", "method"]},
                {"name": "Invoke", "params": ["sender", "e"], "slot": 3}
            ]),
        );
        handler["category"] = json!("delegate");
        let mut slotless = handler.clone();
        slotless["name"] = json!("BadHandler");
        slotless["qualified_name"] = json!("Sample.BadHandler");
        slotless["members"] = json!([{"name": "Invoke"}]);
        let out = temp_dir("delegate");
        let dbs = [db_with(vec![handler, slotless])];
        emit_winrt(&dbs, &["Sample.ThingHandler".into()], "d", &out).unwrap();
        let h = std::fs::read_to_string(out.join("d_winrt.h")).unwrap();
        assert!(h.contains("#define WINRT_IID_ThingHandler (&(const GUID){0x1115b13c"));
        assert!(h.contains("#define WINRT_SLOT_ThingHandler_Invoke 3"));
        assert!(!h.contains("ctor"));
        assert!(emit_winrt(&dbs, &["Sample.BadHandler".into()], "bad", &out).is_err());
    }

    #[test]
    fn sha1_matches_the_fips_vector() {
        let digest = sha1(b"abc");
        assert_eq!(
            crate::hex::lower(&digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn computes_parameterized_iids_like_the_runtime() {
        // IReference`1's GuidAttribute, and the IID the runtime QIs for IReference<Double>.
        let iid = pinterface_iid("61c17706-2d65-11e0-9ae8-d48564015472", &["Double"]).unwrap();
        assert_eq!(iid, "2f2d6c29-5473-5f3e-92e7-96572bb990e2");
        assert!(pinterface_iid("61c17706-2d65-11e0-9ae8-d48564015472", &["Sample.Thing"]).is_err());

        let db = db_with(vec![iface(
            "IBox`1",
            Some("61c17706-2d65-11e0-9ae8-d48564015472"),
            &json!([{"name": "get_Value", "slot": 6}]),
        )]);
        let out = temp_dir("pinterface");
        emit_winrt(&[db], &["Sample.IBox`1<Double>".into()], "p", &out).unwrap();
        let h = std::fs::read_to_string(out.join("p_winrt.h")).unwrap();
        assert!(
            h.contains("#define WINRT_IID_IBox_1_Double (&(const GUID){0x2f2d6c29, 0x5473, 0x5f3e")
        );
        assert!(h.contains("#define WINRT_SLOT_IBox_1_Double_get_Value 6"));
    }

    #[test]
    fn emits_structs_in_order_with_enum_storage() {
        let db = db_with(vec![
            json!({"name": "Kind", "qualified_name": "Sample.Kind", "category": "enum",
                   "underlying": "I32", "values": [{"name": "One", "value": 1}]}),
            json!({"name": "Ticks", "qualified_name": "Sample.Ticks", "category": "struct",
                   "fields": [{"name": "Duration", "type": "I64"}]}),
            json!({"name": "Span", "qualified_name": "Sample.Span", "category": "struct",
                   "fields": [{"name": "Length", "type": "Sample.Ticks"},
                              {"name": "Kind", "type": "Sample.Kind"},
                              {"name": "Scale", "type": "F32"}]}),
            json!({"name": "Odd", "qualified_name": "Sample.Odd", "category": "struct",
                   "fields": [{"name": "Thing", "type": "Sample.IThing"}]}),
        ]);
        let out = temp_dir("structs");
        let dbs = [db];
        emit_winrt(
            &dbs,
            &["Sample.Ticks".into(), "Sample.Span".into()],
            "st",
            &out,
        )
        .unwrap();
        let h = std::fs::read_to_string(out.join("st_winrt.h")).unwrap();
        assert!(h.contains("#include <stdint.h>"));
        assert!(h.contains("typedef struct winrt_Ticks {\n    int64_t Duration;\n} winrt_Ticks;"));
        assert!(h.contains(
            "typedef struct winrt_Span {\n    winrt_Ticks Length;\n    int32_t Kind;\n    float Scale;\n} winrt_Span;"
        ));
        // A nested struct must be wanted first; an interface-typed field is refused.
        assert!(emit_winrt(&dbs, &["Sample.Span".into()], "late", &out).is_err());
        assert!(emit_winrt(&dbs, &["Sample.Odd".into()], "odd", &out).is_err());
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
