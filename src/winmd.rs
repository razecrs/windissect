//! Windows metadata (`.winmd`) extraction.
//!
//! A winmd file is ECMA-335 metadata describing `WinRT` types: interfaces,
//! classes, their methods and the order those methods appear in. There is no
//! code and no PDB, so none of the PE pipeline applies - but the result belongs
//! in the same IR, because the question it answers is the one the archive
//! exists for: what did this API surface look like on this build, and what
//! moved since the last one.
//!
//! The reason this is worth having is the vtable slot and the IID. A `WinRT`
//! interface is a COM interface whose first six slots are `IInspectable` -
//! `QueryInterface`, `AddRef`, Release, `GetIids`, `GetRuntimeClassName`,
//! `GetTrustLevel` - and whose own methods follow in metadata declaration order.
//! So slot = index + 6, exactly, and that number is what anyone calling the
//! interface by hand needs. A `WinRT` delegate inherits `IUnknown` (3 slots)
//! with `Invoke` at slot 3, and interfaces and delegates carry their IID in
//! `GuidAttribute`.
//!
//! That is not a guess. It was verified against a live taskbar: metadata says
//! `IVisualTreeHelperStatics::GetChild` is the fifth declared method, slot 10,
//! and slot 10 is what a working call uses.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use windows_metadata::reader::{Attribute, Index, TypeCategory, TypeDef};
use windows_metadata::{AsRow, HasAttributes, Value};

use crate::model::{
    BinaryInfo, Confidence, Coverage, Database, Kind, Provenance, SCHEMA_VERSION, Signature, Symbol,
};

/// Slots occupied by `IUnknown` before a delegate's `Invoke` method.
const IUNKNOWN_SLOTS: u32 = 3;

/// Slots occupied by `IInspectable` before an interface's own methods begin.
const IINSPECTABLE_SLOTS: u32 = 6;

const fn base_slots(category: &TypeCategory) -> Option<u32> {
    match category {
        TypeCategory::Interface => Some(IINSPECTABLE_SLOTS),
        TypeCategory::Delegate => Some(IUNKNOWN_SLOTS),
        TypeCategory::Class
        | TypeCategory::Enum
        | TypeCategory::Struct
        | TypeCategory::Attribute => None,
    }
}

/// Vtable slot for the method at declaration index `i` after `base` inherited
/// COM slots. A type will never have more methods than `u32::MAX`, so the
/// saturating conversion cannot lose a real value; it only avoids an unchecked
/// `as` cast.
fn slot_of(base: u32, i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX).saturating_add(base)
}

/// Generic parameters of a `TypeDef` indexed by metadata `sequence`.
fn generic_params_of(ty: &TypeDef<'_>) -> Vec<windows_metadata::Type> {
    let mut params: Vec<(u16, String)> = ty
        .generic_params()
        .map(|param| (param.sequence(), param.name().to_string()))
        .collect();
    params.sort_by_key(|(seq, _)| *seq);
    let count = params.last().map_or(0, |(seq, _)| usize::from(*seq) + 1);
    let mut generics: Vec<windows_metadata::Type> = (0..count)
        .map(|i| {
            let seq = u16::try_from(i).unwrap_or(u16::MAX);
            windows_metadata::Type::Generic(format!("T{seq}"), seq)
        })
        .collect();
    for (seq, name) in params {
        if let Some(slot) = generics.get_mut(usize::from(seq)) {
            *slot = windows_metadata::Type::Generic(name, seq);
        }
    }
    generics
}

/// Extract an interface/delegate IID from `GuidAttribute` in canonical
/// lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` form.
fn extract_iid(ty: &TypeDef<'_>) -> Option<String> {
    let attr = ty
        .attributes()
        .find(|attr| attr.name() == "GuidAttribute")?;
    guid_from_attribute(&attr)
}

fn guid_from_attribute(attr: &Attribute<'_>) -> Option<String> {
    let values = attr.value();
    match values.as_slice() {
        [
            (_, Value::U32(d1)),
            (_, Value::U16(d2)),
            (_, Value::U16(d3)),
            (_, Value::U8(b0)),
            (_, Value::U8(b1)),
            (_, Value::U8(b2)),
            (_, Value::U8(b3)),
            (_, Value::U8(b4)),
            (_, Value::U8(b5)),
            (_, Value::U8(b6)),
            (_, Value::U8(b7)),
        ] => Some(format!(
            "{d1:08x}-{d2:04x}-{d3:04x}-{b0:02x}{b1:02x}-{b2:02x}{b3:02x}{b4:02x}{b5:02x}{b6:02x}{b7:02x}"
        )),
        [(_, Value::Utf8(raw))] => normalize_guid_str(raw),
        _ => None,
    }
}

fn normalize_guid_str(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('{').trim_end_matches('}');
    if trimmed.contains('-') {
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() != 5
            || parts[0].len() != 8
            || parts[1].len() != 4
            || parts[2].len() != 4
            || parts[3].len() != 4
            || parts[4].len() != 12
        {
            return None;
        }
    }
    let hex: String = trimmed.chars().filter(|&c| c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let lower = hex.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &lower[0..8],
        &lower[8..12],
        &lower[12..16],
        &lower[16..20],
        &lower[20..32]
    ))
}

/// A resolved interface reference as `Namespace.Name` (with generic arguments if any).
///
/// The crate's `Type` prints its whole internal shape under Debug, which is
/// unreadable in a diff; the parts that matter for identity are the namespace,
/// the name, and any generic arguments.
fn type_name(ty: &windows_metadata::Type) -> String {
    use windows_metadata::Type;
    let named = match ty {
        Type::ClassName(t) | Type::ValueName(t) => t,
        Type::Generic(name, _) => return name.clone(),
        other => return format!("{other:?}"),
    };
    let base = if named.namespace.is_empty() {
        named.name.clone()
    } else {
        format!("{}.{}", named.namespace, named.name)
    };
    if named.generics.is_empty() {
        base
    } else {
        let args: Vec<String> = named.generics.iter().map(type_name).collect();
        format!("{base}<{}>", args.join(", "))
    }
}

/// Named constants of an enum, in declaration order (`value__` is the
/// underlying storage field and has no constant).
fn enum_values(ty: &TypeDef<'_>) -> Vec<serde_json::Value> {
    ty.fields()
        .filter_map(|field| {
            let value = match field.constant()?.value() {
                Value::I32(v) => i64::from(v),
                Value::U32(v) => i64::from(v),
                Value::I16(v) => i64::from(v),
                Value::U16(v) => i64::from(v),
                Value::I8(v) => i64::from(v),
                Value::U8(v) => i64::from(v),
                Value::I64(v) => v,
                _ => return None,
            };
            Some(json!({ "name": field.name(), "value": value }))
        })
        .collect()
}

const fn category_name(category: &TypeCategory) -> &'static str {
    match category {
        TypeCategory::Interface => "interface",
        TypeCategory::Class => "class",
        TypeCategory::Enum => "enum",
        TypeCategory::Struct => "struct",
        TypeCategory::Delegate => "delegate",
        TypeCategory::Attribute => "attribute",
    }
}

/// Methods of a type, paired with the vtable slot they occupy.
///
/// Only interfaces and delegates have a meaningful slot: a runtime class is
/// not called through a vtable of its own, it is reached through the interfaces
/// it implements, so numbering its methods would invent a fact. Constructors
/// (`.ctor`) are CLR metadata only and occupy no COM vtable slot.
fn methods_of(ty: &TypeDef<'_>, base: Option<u32>) -> Vec<serde_json::Value> {
    let mut vtable_index = 0usize;
    ty.methods()
        .map(|m| {
            let params: Vec<String> = m
                .params()
                .map(|p| p.name().to_string())
                .filter(|n| !n.is_empty())
                .collect();
            let mut entry = json!({
                "name": m.name(),
                "params": params,
            });
            if let Some(base_slots) = base
                && m.name() != ".ctor"
            {
                entry["slot"] = json!(slot_of(base_slots, vtable_index));
                vtable_index += 1;
            }
            entry
        })
        .collect()
}

/// One symbol per method of a type, so `wd diff` reports an added, removed or
/// moved API by name rather than as an opaque blob change.
fn method_symbols(ty: &TypeDef<'_>, namespace: &str, name: &str, base: Option<u32>) -> Vec<Symbol> {
    ty.methods()
        .filter(|m| m.name() != ".ctor")
        .enumerate()
        .map(|(i, m)| {
            let id = format!("{namespace}.{name}::{}", m.name());
            Symbol {
                mangled: id.clone(),
                demangled: Some(id.clone()),
                id,
                vaddr: 0,
                rva: 0,
                // The slot is the address-equivalent for metadata: it is how you
                // reach the method, and it is what breaks when a type changes.
                ordinal: base.map(|base_slots| slot_of(base_slots, i)),
                size: 0,
                procedure_size: None,
                is_code: false,
                forwarder: None,
                body_hash: String::new(),
                exported: true,
                library: false,
                kind: Kind::Method,
                coverage: Coverage::Auto,
                provenance: Provenance::Reflection,
                confidence: Confidence::Certain,
                sig: Signature::default(),
                callers: vec![],
                calls: vec![],
                imports: vec![],
            }
        })
        .collect()
}

struct ExtractedTypes {
    classes: Vec<serde_json::Value>,
    symbols: Vec<Symbol>,
    interfaces: usize,
    classes_count: usize,
    enums: usize,
    structs: usize,
    delegates: usize,
    iids: usize,
}

fn collect_types(index: &Index) -> ExtractedTypes {
    let mut types: Vec<TypeDef<'_>> = index.types().filter(|ty| ty.name() != "<Module>").collect();
    types.sort_by_key(|ty| (ty.namespace(), ty.name(), ty.pos()));

    let mut out = ExtractedTypes {
        classes: Vec::with_capacity(types.len()),
        symbols: Vec::new(),
        interfaces: 0,
        classes_count: 0,
        enums: 0,
        structs: 0,
        delegates: 0,
        iids: 0,
    };

    for ty in types {
        let namespace = ty.namespace();
        let name = ty.name();
        let category = ty.category();
        match category {
            TypeCategory::Interface => out.interfaces += 1,
            TypeCategory::Class => out.classes_count += 1,
            TypeCategory::Enum => out.enums += 1,
            TypeCategory::Struct => out.structs += 1,
            TypeCategory::Delegate => out.delegates += 1,
            TypeCategory::Attribute => {}
        }

        let base = base_slots(&category);
        let methods = methods_of(&ty, base);
        let generics = generic_params_of(&ty);

        let mut required = Vec::new();
        let mut default_interface = None;
        for impl_row in ty.interface_impls() {
            let iface_name = type_name(&impl_row.interface(&generics));
            if impl_row.has_attribute("DefaultAttribute") && default_interface.is_none() {
                default_interface = Some(iface_name.clone());
            }
            required.push(iface_name);
        }

        let iid = extract_iid(&ty);
        if iid.is_some() {
            out.iids += 1;
        }

        let mut record = json!({
            "namespace": namespace,
            "name": name,
            "qualified_name": format!("{namespace}.{name}"),
            "category": category_name(&category),
            "methods": methods.len(),
            "interfaces": required,
            "members": methods,
        });
        if let Some(iid) = iid {
            record["iid"] = json!(iid);
        }
        if let Some(default_iface) = default_interface {
            record["default_interface"] = json!(default_iface);
        }
        if matches!(category, TypeCategory::Enum) {
            record["values"] = json!(enum_values(&ty));
        }
        out.classes.push(record);
        out.symbols
            .extend(method_symbols(&ty, namespace, name, base));
    }

    out
}

/// Read a `.winmd` and write an IR database describing its types.
pub fn winmd_command(path: &Path, out: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let sha = crate::hex::lower(&Sha256::digest(&bytes));

    let index = Index::read(path)
        .with_context(|| format!("{} is not readable as ECMA-335 metadata", path.display()))?;

    let extracted = collect_types(&index);
    if extracted.classes.is_empty() {
        bail!("{} contained no types", path.display());
    }

    let type_count = extracted.classes.len();
    let db = Database {
        schema: SCHEMA_VERSION,
        generated: crate::date_today(),
        tool: "rust: windows-metadata (ECMA-335)".into(),
        binary: BinaryInfo {
            file: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.winmd")
                .to_string(),
            sha256: Some(sha),
            image_size: Some(bytes.len() as u64),
            ..Default::default()
        },
        symbols: extracted.symbols,
        type_recovery: json!({
            "source": "winmd-ecma335",
            "status": "recovered",
            "types": type_count,
            "interfaces": extracted.interfaces,
            "classes": extracted.classes_count,
            "enums": extracted.enums,
            "structs": extracted.structs,
            "delegates": extracted.delegates,
            "iids": extracted.iids,
        }),
        classes: extracted.classes,
        ..Default::default()
    };

    let json = serde_json::to_vec_pretty(&db)?;
    crate::diff::atomic_write(out, &json)?;

    println!(
        "{}: {} types ({} interfaces, {} classes, {} enums, {} structs, {} delegates, {} IIDs), \
         {} methods -> {}",
        db.binary.file,
        type_count,
        extracted.interfaces,
        extracted.classes_count,
        extracted.enums,
        extracted.structs,
        extracted.delegates,
        extracted.iids,
        db.symbols.len(),
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use windows_metadata::writer::{
        AttributeType, File, HasAttribute, MemberRefParent, TypeDefOrRef, TypeOrMethodDef,
    };
    use windows_metadata::{
        GenericParamAttributes, MethodAttributes, MethodCallAttributes, MethodImplAttributes,
        ParamAttributes, Signature as WinmdSignature, Type, TypeAttributes,
    };

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("windissect-winmd-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn guid_attr_ctor(file: &mut File) -> AttributeType {
        let attr_ref = file.TypeRef("Windows.Foundation.Metadata", "GuidAttribute");
        let sig = WinmdSignature {
            flags: MethodCallAttributes::HASTHIS,
            return_type: Type::Void,
            types: vec![
                Type::U32,
                Type::U16,
                Type::U16,
                Type::U8,
                Type::U8,
                Type::U8,
                Type::U8,
                Type::U8,
                Type::U8,
                Type::U8,
                Type::U8,
            ],
        };
        AttributeType::MemberRef(file.MemberRef(".ctor", &sig, MemberRefParent::TypeRef(attr_ref)))
    }

    #[allow(clippy::too_many_arguments)]
    fn add_guid_attr(
        file: &mut File,
        target: HasAttribute,
        ctor: AttributeType,
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    ) {
        let args = [
            (String::new(), Value::U32(d1)),
            (String::new(), Value::U16(d2)),
            (String::new(), Value::U16(d3)),
            (String::new(), Value::U8(d4[0])),
            (String::new(), Value::U8(d4[1])),
            (String::new(), Value::U8(d4[2])),
            (String::new(), Value::U8(d4[3])),
            (String::new(), Value::U8(d4[4])),
            (String::new(), Value::U8(d4[5])),
            (String::new(), Value::U8(d4[6])),
            (String::new(), Value::U8(d4[7])),
        ];
        file.Attribute(target, ctor, &args);
    }

    fn build_sample_winmd(extra_method: bool) -> Vec<u8> {
        let mut file = File::new("Sample.winmd");
        add_sample_interfaces(&mut file, extra_method);
        add_sample_delegate_and_class(&mut file);
        file.into_stream()
    }

    fn add_sample_interfaces(file: &mut File, extra_method: bool) {
        let guid_ctor = guid_attr_ctor(file);
        let void_sig = WinmdSignature {
            flags: MethodCallAttributes::HASTHIS,
            return_type: Type::Void,
            types: vec![],
        };
        let one_param_sig = WinmdSignature {
            flags: MethodCallAttributes::HASTHIS,
            return_type: Type::Void,
            types: vec![Type::U32],
        };
        let iface_flags =
            TypeAttributes::Public | TypeAttributes::Interface | TypeAttributes::WindowsRuntime;
        let method_flags =
            MethodAttributes::Public | MethodAttributes::Virtual | MethodAttributes::Abstract;

        // 1. Standard WinRT interface with GuidAttribute.
        let iwidget = file.TypeDef("Sample", "IWidget", TypeDefOrRef::default(), iface_flags);
        add_guid_attr(
            file,
            HasAttribute::TypeDef(iwidget),
            guid_ctor,
            0x1234_5678,
            0x9abc,
            0xdef0,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        );
        if extra_method {
            let _ = file.MethodDef(
                "Inserted",
                &void_sig,
                method_flags,
                MethodImplAttributes::Runtime,
            );
        }
        let _ = file.MethodDef(
            "GetValue",
            &one_param_sig,
            method_flags,
            MethodImplAttributes::Runtime,
        );
        let _ = file.Param("value", 1, ParamAttributes::Out);

        // 2. Generic interface implementing another generic interface (`IVector`1 : IIterable`1<T>`).
        let ivector = file.TypeDef("Sample", "IVector`1", TypeDefOrRef::default(), iface_flags);
        file.GenericParam(
            "T",
            TypeOrMethodDef::TypeDef(ivector),
            0,
            GenericParamAttributes::None,
        );
        add_guid_attr(
            file,
            HasAttribute::TypeDef(ivector),
            guid_ctor,
            0xaaaa_bbbb,
            0xcccc,
            0xdddd,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        let iterable = Type::ClassName(windows_metadata::TypeName {
            namespace: "Sample".into(),
            name: "IIterable`1".into(),
            generics: vec![Type::Generic("T".into(), 0)],
        });
        file.InterfaceImpl(ivector, &iterable);
        let _ = file.MethodDef(
            "GetAt",
            &one_param_sig,
            method_flags,
            MethodImplAttributes::Runtime,
        );
        let _ = file.Param("index", 1, ParamAttributes::In);
    }

    fn add_sample_delegate_and_class(file: &mut File) {
        let string_guid_ref = file.TypeRef("System.Runtime.InteropServices", "GuidAttribute");
        let string_guid_ctor = AttributeType::MemberRef(file.MemberRef(
            ".ctor",
            &WinmdSignature {
                flags: MethodCallAttributes::HASTHIS,
                return_type: Type::Void,
                types: vec![Type::String],
            },
            MemberRefParent::TypeRef(string_guid_ref),
        ));
        let default_attr_ref = file.TypeRef("Windows.Foundation.Metadata", "DefaultAttribute");
        let default_ctor = AttributeType::MemberRef(file.MemberRef(
            ".ctor",
            &WinmdSignature::default(),
            MemberRefParent::TypeRef(default_attr_ref),
        ));
        let void_sig = WinmdSignature {
            flags: MethodCallAttributes::HASTHIS,
            return_type: Type::Void,
            types: vec![],
        };
        let one_param_sig = WinmdSignature {
            flags: MethodCallAttributes::HASTHIS,
            return_type: Type::Void,
            types: vec![Type::U32],
        };
        let method_flags =
            MethodAttributes::Public | MethodAttributes::Virtual | MethodAttributes::Abstract;

        // 3. Delegate with .ctor + Invoke and string-form GuidAttribute.
        let delegate_base = TypeDefOrRef::TypeRef(file.TypeRef("System", "MulticastDelegate"));
        let handler = file.TypeDef(
            "Sample",
            "WidgetHandler",
            delegate_base,
            TypeAttributes::Public | TypeAttributes::Sealed | TypeAttributes::WindowsRuntime,
        );
        file.Attribute(
            HasAttribute::TypeDef(handler),
            string_guid_ctor,
            &[(
                String::new(),
                Value::Utf8("{ABCDEF01-2345-6789-ABCD-EF0123456789}".into()),
            )],
        );
        let _ = file.MethodDef(
            ".ctor",
            &WinmdSignature {
                flags: MethodCallAttributes::HASTHIS,
                return_type: Type::Void,
                types: vec![Type::Object, Type::ISize],
            },
            MethodAttributes::Public
                | MethodAttributes::RTSpecialName
                | MethodAttributes::SpecialName,
            MethodImplAttributes::Runtime,
        );
        let _ = file.MethodDef(
            "Invoke",
            &void_sig,
            method_flags,
            MethodImplAttributes::Runtime,
        );

        // 4. Runtime class with DefaultAttribute on InterfaceImpl and no GuidAttribute.
        let obj_base = TypeDefOrRef::TypeRef(file.TypeRef("System", "Object"));
        let widget = file.TypeDef(
            "Sample",
            "Widget",
            obj_base,
            TypeAttributes::Public | TypeAttributes::Sealed | TypeAttributes::WindowsRuntime,
        );
        let impl_row = file.InterfaceImpl(widget, &Type::class_named("Sample", "IWidget"));
        file.Attribute(HasAttribute::InterfaceImpl(impl_row), default_ctor, &[]);
        let _ = file.MethodDef(
            "GetValue",
            &one_param_sig,
            MethodAttributes::Public,
            MethodImplAttributes::Runtime,
        );
    }

    #[test]
    fn extracts_iids_generics_delegates_and_classes_into_verified_ir() {
        let root = temp_dir("extract");
        let winmd_path = root.join("Sample.winmd");
        let out_path = root.join("Sample.json");
        fs::write(&winmd_path, build_sample_winmd(false)).unwrap();

        winmd_command(&winmd_path, &out_path).unwrap();

        let db: Database = serde_json::from_slice(&fs::read(&out_path).unwrap()).unwrap();
        assert!(crate::verify::run_profile(&db, None));
        assert_eq!(db.classes.len(), 4);
        assert_eq!(db.type_recovery["iids"], 3);

        let iwidget = db
            .classes
            .iter()
            .find(|c| c["qualified_name"] == "Sample.IWidget")
            .unwrap();
        assert_eq!(iwidget["iid"], "12345678-9abc-def0-1122-334455667788");
        assert_eq!(iwidget["members"][0]["name"], "GetValue");
        assert_eq!(iwidget["members"][0]["slot"], 6);

        let ivector = db
            .classes
            .iter()
            .find(|c| c["qualified_name"] == "Sample.IVector`1")
            .unwrap();
        assert_eq!(ivector["iid"], "aaaabbbb-cccc-dddd-0102-030405060708");
        assert_eq!(ivector["interfaces"][0], "Sample.IIterable`1<T>");

        let handler = db
            .classes
            .iter()
            .find(|c| c["qualified_name"] == "Sample.WidgetHandler")
            .unwrap();
        assert_eq!(handler["iid"], "abcdef01-2345-6789-abcd-ef0123456789");
        assert!(handler["members"][0].get("slot").is_none());
        assert_eq!(handler["members"][1]["name"], "Invoke");
        assert_eq!(handler["members"][1]["slot"], 3);

        let widget = db
            .classes
            .iter()
            .find(|c| c["qualified_name"] == "Sample.Widget")
            .unwrap();
        assert!(widget.get("iid").is_none());
        assert_eq!(widget["default_interface"], "Sample.IWidget");
        assert!(widget["members"][0].get("slot").is_none());

        let invoke_sym = db
            .symbols
            .iter()
            .find(|s| s.id == "Sample.WidgetHandler::Invoke")
            .unwrap();
        assert_eq!(invoke_sym.ordinal, Some(3));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn diff_detects_winmd_vtable_slot_drift() {
        let root = temp_dir("diff");
        let old_winmd = root.join("old.winmd");
        let new_winmd = root.join("new.winmd");
        let old_ir = root.join("old.json");
        let new_ir = root.join("new.json");

        fs::write(&old_winmd, build_sample_winmd(false)).unwrap();
        fs::write(&new_winmd, build_sample_winmd(true)).unwrap();
        winmd_command(&old_winmd, &old_ir).unwrap();
        winmd_command(&new_winmd, &new_ir).unwrap();

        let old_db: Database = serde_json::from_slice(&fs::read(&old_ir).unwrap()).unwrap();
        let new_db: Database = serde_json::from_slice(&fs::read(&new_ir).unwrap()).unwrap();
        let report = crate::diff::compare(&old_db, &new_db);

        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].id, "Sample.IWidget::Inserted");
        assert_eq!(report.added[0].ordinal, Some(6));
        assert!(
            report
                .modified
                .iter()
                .any(|c| c.id == "Sample.IWidget::GetValue"
                    && c.flags.ordinal.get()
                    && c.before.ordinal == Some(6)
                    && c.after.ordinal == Some(7))
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_invalid_guid_strings() {
        assert_eq!(
            normalize_guid_str("{12345678-9ABC-DEF0-1122-334455667788}"),
            Some("12345678-9abc-def0-1122-334455667788".into())
        );
        assert_eq!(normalize_guid_str("not-a-guid"), None);
        assert_eq!(
            normalize_guid_str("1234-5678-9abc-def0-1122334455667788"),
            None
        );
    }
}
