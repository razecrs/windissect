//! Emitters over the IR. First target: a reconstructed C++ class header.

use crate::model::{Database, Kind, Symbol, TypeText};
use std::collections::{BTreeMap, BTreeSet};

pub fn build_forward_declarations(db: &Database) -> String {
    let mut ns_classes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let all_classes = classes(db);
    for (ns, class, _) in &all_classes {
        let mut clean_ns = ns.clone();
        for c in &all_classes {
            if clean_ns.ends_with(&format!("::{}", c.1))
                && let Some(stripped) = clean_ns.strip_suffix(&format!("::{}", c.1))
            {
                clean_ns = stripped.to_string();
            }
        }
        if clean_ns == "global" {
            clean_ns = "".to_string();
        }
        ns_classes
            .entry(clean_ns)
            .or_default()
            .insert(class.clone());
    }

    // Automatically extract all DirectUI structs/classes referenced in function return types or parameters
    for s in &db.symbols {
        let mut check_type = |t: &str| {
            let mut search = t;
            while let Some(pos) = search.find("DirectUI::") {
                let rest = &search[pos + 10..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    ns_classes
                        .entry("DirectUI".to_string())
                        .or_default()
                        .insert(name);
                }
                search = rest;
            }
        };
        if let Some(ret) = &s.sig.ret {
            check_type(&ret.text);
        }
        for p in &s.sig.params {
            check_type(&p.text);
        }
    }

    let mut out = String::new();
    out.push_str("#pragma once\n\n");
    out.push_str("#include <cstdint>\n\n");
    out.push_str("// Forward declarations (automatically generated)\n");
    out.push_str("struct IXmlReader; struct IStream; struct IUnknown; struct IDuiBehavior;\n");
    out.push_str("struct IDCompositionVisual; struct IRawElementProviderSimple;\n");
    out.push_str("struct IWICImagingFactory; struct IWICBitmapSource; struct IWICPalette;\n");
    out.push_str("struct tagPOINT; struct tagRECT; struct tagSIZE; struct tagRGBQUAD;\n");
    out.push_str("struct HFONT__; struct HICON__; struct HBITMAP__; struct HWND__; struct HDC__; struct HINSTANCE__;\n");
    out.push_str("enum TouchKeyboardNotificationsDesired : int; enum XmlNodeType : int; enum StructureChangeType : int;\n");
    out.push_str("enum TOUCHTOOLTIP_INPUT : int; enum TOUCHTOOLTIP_TYPE : int;\n");
    out.push_str(
        "enum TOUCHTOOLTIP_OPTION_FLAGS : int; enum TOUCHTOOLTIP_LAYOUT_DIRECTION : int;\n",
    );
    out.push_str("enum TOUCHTOOLTIP_PLACEMENT : int; enum TOUCHTOOLTIP_CREATE_FLAGS : int;\n");
    out.push_str("enum DWRITE_FONT_WEIGHT : int; enum DWRITE_FONT_STYLE : int; enum DWRITE_FONT_STRETCH : int;\n\n");

    out.push_str(
        "namespace D2D1 { class Matrix3x2F; class ID2D1Bitmap; class ID2D1RenderTarget; }\n",
    );
    out.push_str("namespace Gdiplus {\n");
    out.push_str("    enum Status : int; enum WrapMode : int; enum BrushType : int; enum SmoothingMode : int; enum CombineMode : int; enum FillMode : int;\n");
    out.push_str("    class Bitmap; class Graphics; class Image; class Matrix; class Brush; class Pen; class Font; class PathData; class Color; class Rect; class GraphicsPath; class LinearGradientBrush; class PathGradientBrush; class SolidBrush; class RectF; class PointF; class SizeF; class Point; class Size;\n");
    out.push_str("    struct ColorMatrix;\n");
    out.push_str("}\n\n");

    out.push_str("namespace SWF { class SWF; class Fluster; class Movie; namespace Tag { enum TagID : int; class Tag; } }\n");
    out.push_str("namespace Library { class Stream; template<typename T> class SimpleVector; }\n");
    out.push_str(
        "namespace Windows { namespace UI { namespace Immersive { class CConstraint; } } }\n",
    );
    out.push_str("namespace Microsoft { namespace WRL { namespace Wrappers { class CriticalSection; } } }\n\n");

    out.push_str("namespace DirectUI {\n");
    out.push_str("    enum StringRunStyles : int; enum _DUI_PARSE_STATE : int; enum TOUCHTOOLTIP_ALIGNMENT : int;\n");
    out.push_str("    namespace StyleSheetCache { class CSheetEntry; }\n");
    out.push_str("    namespace ParserTools { class ValueParser; struct ExprNode; enum TokenType : int; enum ExprNodeType : int; }\n");
    out.push_str("    template<typename T, int N> class DynamicArray;\n\n");

    if let Some(directui_classes) = ns_classes.get("DirectUI") {
        let skip_classes = [
            "DynamicArray",
            "ParserTools",
            "StyleSheetCache",
            "Impl",
            "Internal",
            "Details",
            "Wrappers",
            "HandleTraits",
            "wil",
            "wistd",
            "StringRunStyles",
            "_DUI_PARSE_STATE",
            "TOUCHTOOLTIP_ALIGNMENT",
        ];
        // Names used as a namespace segment must not also be forward-declared as
        // a class, or the class definition clashes (e.g. DirectUI::BinaryFile).
        let ns_segments: BTreeSet<String> = db
            .symbols
            .iter()
            .filter_map(|s| s.sig.namespace.clone())
            .flat_map(|n| n.split("::").map(String::from).collect::<Vec<_>>())
            .collect();
        let mut line = String::from("    class ");
        let mut first = true;
        for c in directui_classes {
            if c.is_empty()
                || c.contains(' ')
                || c.contains('<')
                || skip_classes.contains(&c.as_str())
                || ns_segments.contains(c)
            {
                continue;
            }
            if !first {
                line.push_str("; class ");
            }
            first = false;
            line.push_str(c);
            if line.len() > 100 {
                out.push_str(&line);
                out.push_str(";\n");
                line = String::from("    class ");
                first = true;
            }
        }
        if !first {
            out.push_str(&line);
            out.push_str(";\n");
        }
    }

    out.push_str("\n    struct Event; struct PropertyInfo; struct IElementListener;\n");
    out.push_str("    struct IClassInfo; struct Fill; struct DepRecs; struct UpdateCache;\n");
    out.push_str(
        "    struct InputEvent; struct IDialogElement; struct ScaledRECT; struct ScaledSIZE;\n",
    );
    out.push_str("    struct LINEINFO; struct EnumMap; struct XMLParserCond; struct Cond; struct Decl; struct ClassData;\n");
    out.push_str("}\n\n");

    // Generic target namespaces. DUI70 keeps its richer compatibility block
    // above; every other database is derived from the IR rather than a fixed
    // namespace allow-list.
    for (ns, names) in &ns_classes {
        if ns.is_empty() || ns == "DirectUI" {
            continue;
        }
        let parts: Vec<&str> = ns.split("::").filter(|p| !p.is_empty()).collect();
        for part in &parts {
            out.push_str(&format!("namespace {part} {{ "));
        }
        for name in names {
            if !name.contains(['<', ' ', '`']) {
                out.push_str(&format!("class {name}; "));
            }
        }
        for _ in &parts {
            out.push_str("} ");
        }
        out.push('\n');
    }
    out.push('\n');

    out
}

/// Reconstruct a single C++ class declaration from the IR.
pub fn cpp_class(db: &Database, ns: &str, class: &str) -> String {
    let class_set: BTreeSet<String> = db
        .symbols
        .iter()
        .filter_map(|s| s.sig.class.clone())
        .filter(|c| !c.contains('<'))
        .collect();

    let mut members: Vec<&Symbol> = db
        .symbols
        .iter()
        .filter(|s| {
            !s.library
                && s.sig.parse_ok
                && s.sig.namespace.as_deref().unwrap_or("") == ns
                && s.sig.class.as_deref() == Some(class)
        })
        .collect();

    // Group by access (public, protected, private, then unspecified), method
    // name within, so the header reads like a real declaration.
    let rank = |a: Option<&str>| match a {
        Some("public") => 0,
        Some("protected") => 1,
        Some("private") => 2,
        _ => 3,
    };
    members.sort_by(|a, b| {
        rank(a.sig.access.as_deref())
            .cmp(&rank(b.sig.access.as_deref()))
            .then(a.sig.method.cmp(&b.sig.method))
    });

    // Strip trailing namespace components that are actually class names in the database
    let mut clean_ns = ns.to_string();
    let all_class_names: BTreeSet<String> = db
        .symbols
        .iter()
        .filter_map(|s| s.sig.class.clone())
        .collect();
    for c in &all_class_names {
        if clean_ns.ends_with(&format!("::{c}"))
            && let Some(stripped) = clean_ns.strip_suffix(&format!("::{c}"))
        {
            clean_ns = stripped.to_string();
        }
    }
    let has_ns = !clean_ns.is_empty() && clean_ns != "global";

    let mut out = String::new();
    out.push_str(&build_forward_declarations(db));

    out.push_str(&format!(
        "// Reconstructed from {} by Windissect. {} member(s).\n",
        db.binary.file,
        members.len()
    ));
    let qualified_class = if clean_ns.is_empty() || clean_ns == "global" {
        class.to_string()
    } else {
        format!("{clean_ns}::{class}")
    };
    if let Some(record) = db.classes.iter().find(|record| {
        record
            .get("qualified_name")
            .and_then(serde_json::Value::as_str)
            == Some(qualified_class.as_str())
    }) {
        for base in record
            .get("bases")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = base
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let evidence = base
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let confidence = base
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            out.push_str(&format!(
                "// Base evidence: {name} ({confidence}; {evidence}).\n"
            ));
        }
    }
    if has_ns {
        out.push_str(&format!("namespace {clean_ns} {{\n"));
    }
    out.push_str(&format!("class {class} {{\n"));

    let mut cur = 4u8; // force a label before the first member
    let mut has_dtor = false;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for m in &members {
        let method = m.sig.method.as_deref().unwrap_or("?");
        if method.contains('`') || method.contains('<') || method.contains("operator") {
            continue; // closures, template methods, operator overloads
        }
        // Multiple-inheritance adjustor thunks demangle as "[thunk]:..." — skip.
        if m.demangled
            .as_deref()
            .is_some_and(|d| d.starts_with("[thunk]"))
        {
            continue;
        }
        // Dedup overloads that collapse to one signature after cleaning (e.g.
        // params that both placeholder to void*, or differ only by return type),
        // which C++ rejects.
        let key = format!(
            "{method}|{}",
            m.sig
                .params
                .iter()
                .map(|p| clean_cpp_type(&p.text, class, &class_set))
                .collect::<Vec<_>>()
                .join(",")
        );
        if !seen.insert(key) {
            continue;
        }
        if method.contains("deleting destructor") || method.starts_with('~') {
            if has_dtor {
                continue; // Skip duplicate destructor declarations
            }
            has_dtor = true;
        }

        let acc = rank(m.sig.access.as_deref()) as u8;
        if acc != cur {
            cur = acc;
            let label = ["public", "protected", "private", "public /*unspecified*/"][acc as usize];
            out.push_str(&format!("{label}:\n"));
        }
        out.push_str(&decl_line(m, class, &class_set));
        out.push('\n');
    }
    out.push_str("};\n");
    if has_ns {
        out.push_str(&format!("}} // namespace {clean_ns}\n"));
    }
    out
}

/// One member declaration line with relatable kind and exact raw mangled symbol in comments.
fn decl_line(s: &Symbol, class_name: &str, class_set: &BTreeSet<String>) -> String {
    let sig = &s.sig;
    let method = sig.method.as_deref().unwrap_or("?");
    let mangled = &s.mangled;
    let kind_str = format!("{:?}", s.kind);
    let prov_str = if s.exported {
        "PE Export"
    } else {
        "PDB Internal"
    };

    let mut doc_comment =
        format!("    // Category: {kind_str} | Source: {prov_str}\n    // Symbol: {mangled}\n    ");

    // Handle deleting destructors and normal destructors
    if method.contains("deleting destructor") || method.starts_with('~') {
        let storage = if sig.storage.as_deref() == Some("virtual") {
            "virtual "
        } else {
            ""
        };
        doc_comment.push_str(&format!("{storage}~{class_name}();"));
        return doc_comment;
    }

    let mut line = String::new();
    match sig.storage.as_deref() {
        Some("virtual") => line.push_str("virtual "),
        Some("static") => line.push_str("static "),
        _ => {}
    }
    // ctors/dtors have no return type.
    if !matches!(s.kind, Kind::Ctor | Kind::Dtor)
        && let Some(ret) = &sig.ret
    {
        line.push_str(&clean_cpp_type(&ret.text, class_name, class_set));
        line.push(' ');
    }
    line.push_str(method);
    let params: Vec<String> = sig
        .params
        .iter()
        .map(|p| clean_cpp_type(&p.text, class_name, class_set))
        .collect();
    line.push('(');
    line.push_str(&params.join(", "));
    line.push(')');
    if sig.is_const {
        line.push_str(" const");
    }
    line.push(';');

    doc_comment.push_str(&line);
    doc_comment
}

/// A `class/struct/union/enum X` (or `X<...>`) reference in a type string.
struct TypeRef {
    start: usize,
    end: usize,
    kw: &'static str,
    qual: String,
    template: bool,
}

/// Every elaborated type reference in `text`, left to right.
fn scan_type_refs(text: &str) -> Vec<TypeRef> {
    let b = text.as_bytes();
    let mut refs = Vec::new();
    for kw in ["class", "struct", "union", "enum"] {
        let mut from = 0;
        while let Some(rel) = text[from..].find(kw) {
            let start = from + rel;
            from = start + kw.len();
            if start > 0 && (b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_') {
                continue;
            }
            let ak = start + kw.len();
            if ak >= text.len() || b[ak] != b' ' {
                continue;
            }
            let qs = ak + 1;
            let mut i = qs;
            while i < text.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b':') {
                i += 1;
            }
            if i == qs {
                continue;
            }
            let qual = text[qs..i].trim_end_matches(':').to_string();
            let mut j = i;
            while j < text.len() && b[j] == b' ' {
                j += 1;
            }
            let template = j < text.len() && b[j] == b'<';
            let end = if template { match_angle(text, j) } else { i };
            refs.push(TypeRef {
                start,
                end,
                kw,
                qual,
                template,
            });
        }
    }
    refs.sort_by_key(|r| r.start);
    refs
}

/// Index just past the `>` closing the `<` at `open`.
fn match_angle(text: &str, open: usize) -> usize {
    let b = text.as_bytes();
    let mut depth = 0;
    for (i, byte) in b.iter().enumerate().skip(open) {
        match byte {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// True when a type is nested inside a class, so not forward-declarable.
fn is_nested(qual: &str, class_set: &BTreeSet<String>) -> bool {
    let parts: Vec<&str> = qual.split("::").filter(|s| !s.is_empty()).collect();
    parts.len() > 1
        && parts[..parts.len() - 1]
            .iter()
            .any(|c| class_set.contains(*c))
}

fn clean_cpp_type(s: &str, current_class: &str, class_set: &BTreeSet<String>) -> String {
    let mut cleaned = s.replace("__cdecl", "");

    // General pass: placeholder types C++ cannot forward-declare.
    // enum -> int (ABI-safe); nested or templated class/struct/union -> void*.
    let mut spans: Vec<(usize, usize, &str)> = Vec::new();
    for r in scan_type_refs(&cleaned) {
        let repl = if r.kw == "enum" {
            "int"
        } else if r.template || is_nested(&r.qual, class_set) {
            "void*"
        } else {
            continue;
        };
        spans.push((r.start, r.end, repl));
    }
    // Keep only outermost spans (a template ref contains inner refs), then splice
    // right to left so earlier byte indices stay valid.
    spans.sort_by_key(|s| s.0);
    let mut max_end = 0;
    let mut kept: Vec<(usize, usize, &str)> = Vec::new();
    for sp in spans {
        if sp.0 >= max_end {
            kept.push(sp);
        }
        max_end = max_end.max(sp.1);
    }
    for (start, end, repl) in kept.iter().rev() {
        cleaned.replace_range(*start..*end, repl);
    }
    while cleaned.contains("  ") {
        cleaned = cleaned.replace("  ", " ");
    }
    cleaned = cleaned.trim().to_string();

    // Self-referential class type simplification inside class body
    if !current_class.is_empty() {
        let full_directui = format!("class DirectUI::{current_class}");
        if cleaned.contains(&full_directui) {
            cleaned = cleaned.replace(&full_directui, current_class);
        }
        let full_directui_struct = format!("struct DirectUI::{current_class}");
        if cleaned.contains(&full_directui_struct) {
            cleaned = cleaned.replace(&full_directui_struct, current_class);
        }
    }

    // Sanitize nested struct/enum references like DirectUI::Parent::Child
    if cleaned.contains("STACK_SYMBOL_INFO") {
        cleaned = cleaned.replace("CallstackTracker::STACK_SYMBOL_INFO", "void*");
    }
    if cleaned.contains("SWF::Bits") {
        cleaned = cleaned
            .replace("class SWF::Bits", "void*")
            .replace("SWF::Bits", "void*");
    }
    if cleaned.contains("LineSegment") {
        cleaned = cleaned
            .replace("struct SWF::Shape::LineSegment", "void*")
            .replace("Shape::LineSegment", "void*");
    }
    if cleaned.contains("SWF::Types::BrushType") {
        cleaned = cleaned.replace("enum SWF::Types::BrushType", "int");
    }
    if cleaned.contains("TILING_DATA") {
        cleaned = cleaned
            .replace("ContentTiler::TILING_DATA", "void*")
            .replace("DirectUI::ContentTiler::TILING_DATA", "void*");
    }
    if cleaned.contains("CCacheThread::Invoke") {
        cleaned = cleaned
            .replace(
                "class DirectUI::StyleSheetCache::CCacheThread::Invoke",
                "void",
            )
            .replace("CCacheThread::Invoke", "void");
    }
    if cleaned.contains("::AccessibleButton::ACCESSIBLEROLE") {
        cleaned = cleaned.replace(
            "struct DirectUI::AccessibleButton::ACCESSIBLEROLE",
            "uintptr_t",
        );
    }
    if cleaned.contains("::TouchTooltipTimings::TIMINGS") {
        cleaned = cleaned.replace("struct DirectUI::TouchTooltipTimings::TIMINGS", "uintptr_t");
    }
    if cleaned.contains("::Internal::ListenerData") {
        cleaned = cleaned.replace("struct DirectUI::Internal::ListenerData", "uintptr_t");
    }
    if cleaned.contains("::SmoothDot::DRAW_PARAMS") {
        cleaned = cleaned.replace("struct DirectUI::SmoothDot::DRAW_PARAMS", "uintptr_t");
    }
    if cleaned.contains("::CActivityOverlay::FUNCMODE") {
        cleaned = cleaned.replace("enum DirectUI::CActivityOverlay::FUNCMODE", "int");
    }
    if cleaned.contains("SWF::Tag::TagID") {
        cleaned = cleaned.replace("enum SWF::Tag::TagID", "int");
    }
    if cleaned.contains("::GraphicsPath") {
        cleaned = cleaned.replace("class Gdiplus::GraphicsPath", "void");
    }
    if cleaned.contains("::SmoothingMode") {
        cleaned = cleaned.replace("enum Gdiplus::SmoothingMode", "int");
    }
    if cleaned.contains("::DUIXmlParser::ParsedArg") {
        cleaned = cleaned.replace("union DirectUI::DUIXmlParser::ParsedArg", "void*");
    }
    if cleaned.contains("CheckedStateFlags") {
        cleaned = cleaned
            .replace("enum DirectUI::CheckedStateFlags", "int")
            .replace("enum CheckedStateFlags", "int");
    }
    if cleaned.contains("::_DUI_PARSE_STATE") {
        cleaned = cleaned.replace("enum DirectUI::_DUI_PARSE_STATE", "int");
    }
    if cleaned.contains("ElementProvider")
        && !cleaned.contains("DirectUI::ElementProvider")
        && !cleaned.contains("IRaw")
    {
        cleaned = cleaned.replace("ElementProvider", "class DirectUI::ElementProvider");
    }
    if cleaned.contains("Schema::Event") {
        cleaned = cleaned
            .replace("enum DirectUI::Schema::Event", "int")
            .replace("Schema::Event", "int");
    }
    if cleaned.contains("::Impl::ParserCacheEntry") {
        cleaned = cleaned.replace("struct DirectUI::Impl::ParserCacheEntry", "void*");
    }
    if cleaned.contains("InvokeHelper::InvokeArgs") {
        cleaned = cleaned.replace("InvokeHelper::InvokeArgs", "void");
    }
    if cleaned.contains("class SWF::Tag") {
        cleaned = cleaned.replace("class SWF::Tag", "void*");
    }
    if cleaned.contains("SWF::SWF") {
        cleaned = cleaned
            .replace("class SWF::SWF", "class SWF")
            .replace("SWF::SWF", "SWF");
    }
    if cleaned.contains("class SWF::Movie") || cleaned.contains("SWF::Movie") {
        cleaned = cleaned
            .replace("class SWF::Movie", "void*")
            .replace("SWF::Movie", "void*");
    }
    if cleaned.contains("class SWF::Fluster") || cleaned.contains("SWF::Fluster") {
        cleaned = cleaned
            .replace("class SWF::Fluster", "void*")
            .replace("SWF::Fluster", "void*");
    }
    cleaned
}

/// List the (namespace, class) pairs present, with member counts.
pub fn classes(db: &Database) -> Vec<(String, String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for s in &db.symbols {
        if s.library || !s.sig.parse_ok {
            continue;
        }
        if let Some(class) = &s.sig.class {
            // Names that are namespaces (or namespace/class collisions) cannot
            // be emitted as standalone classes without a redeclaration clash.
            const NS_NAMES: &[&str] = &[
                "DirectUI",
                "SWF",
                "Library",
                "Windows",
                "Microsoft",
                "Gdiplus",
                "D2D1",
                "Immersive",
                "UI",
                "WRL",
                "Wrappers",
                "Tag",
                "BinaryFile",
                "Impl",
                "Internal",
                "ParserTools",
                "StyleSheetCache",
                "type_info",
                "exception",
            ];
            if class.contains('<') || NS_NAMES.contains(&class.as_str()) {
                continue;
            }
            let ns = s.sig.namespace.clone().unwrap_or_default();
            *counts.entry((ns, class.clone())).or_default() += 1;
        }
    }
    let mut v: Vec<_> = counts.into_iter().map(|((n, c), k)| (n, c, k)).collect();
    v.sort_by_key(|item| std::cmp::Reverse(item.2));
    v
}

pub fn sanitize_filename(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean_str = clean.trim_matches('_');
    if clean_str.is_empty() {
        "AnonClass".to_string()
    } else {
        clean_str.to_string()
    }
}

pub fn category_dir(class: &str) -> &'static str {
    if class.contains("Layout") {
        "layouts"
    } else if class.contains("Provider")
        || class.contains("Accessible")
        || class.contains("Proxy")
        || class.contains("Uia")
    {
        "accessibility"
    } else if class.contains("Parser")
        || class.contains("Xml")
        || class.contains("Sheet")
        || class.contains("ByteCode")
    {
        "parsing"
    } else if class.contains("Animation") || class.contains("PVL") {
        "animation"
    } else if class.contains("Button")
        || class.contains("Edit")
        || class.contains("Text")
        || class.contains("Progress")
        || class.contains("Bar")
        || class.contains("Select")
        || class.contains("List")
        || class.contains("View")
        || class.contains("Combobox")
    {
        "controls"
    } else if class.contains("Behavior") {
        "behaviors"
    } else if class.contains("Value")
        || class.contains("Font")
        || class.contains("Color")
        || class.contains("Expression")
        || class.contains("UID")
    {
        "values"
    } else if class.contains("Element") || class.contains("HWND") || class.contains("ClassInfo") {
        "core"
    } else if class.contains("Macro")
        || class.contains("Page")
        || class.contains("Repeater")
        || class.contains("Viewer")
        || class.contains("Dialog")
        || class.contains("Expand")
        || class.contains("XBaby")
    {
        "containers"
    } else {
        "utilities"
    }
}

/// Emit all C++ class headers into `headers/<category>/` subdirectories.
pub fn emit_all_headers(db: &Database, out_dir: &std::path::Path) -> anyhow::Result<usize> {
    use std::fs;

    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    let resolved_out = if out_dir.exists() {
        fs::canonicalize(out_dir)?
    } else {
        let name = out_dir
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("output directory must have a final component"))?;
        let parent = out_dir
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        fs::canonicalize(parent)?.join(name)
    };
    anyhow::ensure!(
        resolved_out != cwd,
        "refusing to replace the current directory"
    );
    anyhow::ensure!(
        resolved_out.parent().is_some(),
        "refusing to replace a filesystem root"
    );

    // Generated directories are replaced as a unit to avoid mixing builds.
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir)?;

    let categories = [
        "core",
        "controls",
        "layouts",
        "parsing",
        "animation",
        "accessibility",
        "containers",
        "values",
        "behaviors",
        "utilities",
    ];
    for cat in &categories {
        fs::create_dir_all(out_dir.join(cat))?;
    }

    let class_list = classes(db);
    let mut count = 0;
    let mut includes_list = Vec::new();

    fs::write(out_dir.join("windissect_abi.h"), abi_metadata_header(db))?;
    includes_list.push("windissect_abi.h".to_string());
    fs::write(out_dir.join("windissect_vcalls.h"), vcall_header(db))?;
    includes_list.push("windissect_vcalls.h".to_string());
    fs::write(out_dir.join("windissect_calls.h"), direct_call_header(db))?;

    // Check for duplicate class names across namespaces
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, class, _) in &class_list {
        let clean = sanitize_filename(class);
        *name_counts.entry(clean).or_default() += 1;
    }

    for (ns, class, _) in &class_list {
        let cat = category_dir(class);
        let clean = sanitize_filename(class);
        let file_name = if name_counts.get(&clean).copied().unwrap_or(0) <= 1 {
            format!("{clean}.h")
        } else {
            let ns_clean = if ns.is_empty() {
                "global".to_string()
            } else {
                sanitize_filename(ns)
            };
            format!("{ns_clean}_{clean}.h")
        };
        let code = cpp_class(db, ns, class);
        let rel_path = format!("{cat}/{file_name}");
        fs::write(out_dir.join(&rel_path), code)?;
        includes_list.push(rel_path);
        count += 1;
    }

    let target = std::path::Path::new(&db.binary.file)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(&db.binary.file);
    let target_file = sanitize_filename(target);
    // Master C++ header.
    let mut master_hdr = String::new();
    master_hdr.push_str(&format!(
        "// Windissect master C++ header for {}\n// Validated dialects: C++17, C++20, C++23, and C++26 draft.\n#pragma once\n\n#if defined(_MSVC_LANG)\n#  define WINDISSECT_CPLUSPLUS _MSVC_LANG\n#else\n#  define WINDISSECT_CPLUSPLUS __cplusplus\n#endif\n#if WINDISSECT_CPLUSPLUS < 201703L\n#  error \"Windissect C++ output requires C++17 or newer\"\n#endif\n\n",
        db.binary.file
    ));
    for inc in &includes_list {
        master_hdr.push_str(&format!("#include \"{}\"\n", inc));
    }
    fs::write(out_dir.join(format!("{target_file}.h")), master_hdr)?;

    // Flat C exports header (dui70_c.h)
    let mut c_hdr = String::new();
    let guard = format!("{}_C_H", target_file.to_ascii_uppercase());
    c_hdr.push_str(&format!("// Flat C exports observed in {}. Unknown ABIs are intentionally not declared.\n// Validated dialects: ISO C17/C23/C26 draft and Windissect C20 (C ABI under C++20).\n#pragma once\n#ifndef {guard}\n#define {guard}\n#if defined(__cplusplus)\n#  if __cplusplus < 202002L\n#    define WINDISSECT_C20_PROFILE 0\n#  else\n#    define WINDISSECT_C20_PROFILE 1\n#  endif\nextern \"C\" {{\n#else\n#  if defined(__STDC_VERSION__) && __STDC_VERSION__ < 201710L\n#    error \"Windissect C output requires C17 or newer\"\n#  endif\n#  define WINDISSECT_C20_PROFILE 0\n#  define WINDISSECT_C_STANDARD __STDC_VERSION__\n#endif\n\n", db.binary.file));
    for s in &db.symbols {
        if s.library || !s.exported || s.mangled.starts_with('?') {
            continue;
        }
        c_hdr.push_str(&format!("// Export: {} (ABI unverified)\n", s.mangled));
    }
    c_hdr.push_str(&format!(
        "\n#ifdef __cplusplus\n}} // extern \"C\"\n#endif\n#endif // {guard}\n"
    ));
    fs::write(out_dir.join(format!("{target_file}_c.h")), c_hdr)?;

    Ok(count)
}

/// Emit machine-consumable ABI evidence without pretending incomplete RTTI is
/// a compilable class definition. Exact PDB field offsets and tentative
/// PE-vftable bounds remain explicitly labelled by their evidence strings.
fn abi_metadata_header(db: &Database) -> String {
    let mut out = String::from(
        "// Windissect recovered ABI metadata — DO NOT EDIT.\n// Portable across C++17, C++20, C++23, and C++26 draft modes.\n#pragma once\n#include <cstddef>\n#include <cstdint>\n\nnamespace windissect_abi {\nstruct TypeLayout { const char* name; std::uint64_t size; const char* kind; };\nstruct FieldLayout { const char* owner; const char* name; std::uint32_t type_index; std::uint64_t offset; bool is_static; };\nstruct FieldObservation { const char* owner; const char* suggested_name; std::uint64_t offset; std::uint32_t width; const char* access; std::uint32_t evidence_rva; const char* evidence_symbol; const char* confidence; };\nstruct BaseLayout { const char* derived; const char* base; std::int64_t offset; bool is_virtual; const char* evidence; const char* confidence; };\nstruct VTableLayout { const char* name; std::uint32_t rva; std::uint32_t slots; const char* evidence; const char* confidence; };\nstruct VTableSlotLayout { std::uint32_t table_rva; std::uint32_t slot; std::uint32_t target_rva; const char* target_id; const char* target_name; bool ambiguous; std::int32_t this_adjustment; };\n\n",
    );
    out.push_str("inline constexpr TypeLayout types[] = {\n");
    for ty in &db.types {
        let name = cpp_string(
            ty.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        let kind = cpp_string(
            ty.get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
        );
        let size = ty
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        out.push_str(&format!("    {{\"{name}\", {size}ULL, \"{kind}\"}},\n"));
    }
    out.push_str("    {nullptr, 0, nullptr},\n};\ninline constexpr std::size_t type_count = (sizeof(types) / sizeof(types[0])) - 1;\ninline constexpr FieldLayout fields[] = {\n");
    for ty in &db.types {
        let owner = cpp_string(
            ty.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        for field in ty
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = cpp_string(
                field
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            );
            let type_index = field
                .get("type_index")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let offset = field
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let is_static = field
                .get("is_static")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            out.push_str(&format!(
                "    {{\"{owner}\", \"{name}\", {type_index}U, {offset}ULL, {is_static}}},\n"
            ));
        }
    }
    out.push_str("    {nullptr, nullptr, 0, 0, false},\n};\ninline constexpr std::size_t field_count = (sizeof(fields) / sizeof(fields[0])) - 1;\ninline constexpr FieldObservation field_observations[] = {\n");
    for ty in &db.types {
        let owner = cpp_string(
            ty.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        for observation in ty
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let suggested_name = observation
                .get("suggested_name")
                .and_then(serde_json::Value::as_str)
                .map_or("nullptr".to_string(), |s| format!("\"{}\"", cpp_string(s)));
            let offset = observation
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let width = observation
                .get("width")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let access = cpp_string(
                observation
                    .get("access")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
            );
            let evidence_rva = observation
                .get("evidence_rva")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let evidence_symbol = cpp_string(
                observation
                    .get("evidence_symbol")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            );
            let confidence = cpp_string(
                observation
                    .get("confidence")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("tentative"),
            );
            out.push_str(&format!("    {{\"{owner}\", {suggested_name}, {offset}ULL, {width}U, \"{access}\", 0x{evidence_rva:X}U, \"{evidence_symbol}\", \"{confidence}\"}},\n"));
        }
    }
    out.push_str("    {nullptr, nullptr, 0, 0, nullptr, 0, nullptr, nullptr},\n};\ninline constexpr std::size_t field_observation_count = (sizeof(field_observations) / sizeof(field_observations[0])) - 1;\ninline constexpr BaseLayout bases[] = {\n");
    let mut seen_bases = BTreeSet::new();
    for owner in db.types.iter().chain(db.classes.iter()) {
        let derived = owner
            .get("qualified_name")
            .or_else(|| owner.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        for base in owner
            .get("bases")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = base
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let evidence = base
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("pdb-tpi");
            let confidence = base
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("certain");
            let offset = base
                .get("offset")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let is_virtual = base
                .get("is_virtual")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if seen_bases.insert((derived.to_string(), name.to_string())) {
                out.push_str(&format!(
                    "    {{\"{}\", \"{}\", {offset}LL, {is_virtual}, \"{}\", \"{}\"}},\n",
                    cpp_string(derived),
                    cpp_string(name),
                    cpp_string(evidence),
                    cpp_string(confidence)
                ));
            }
        }
    }
    out.push_str("    {nullptr, nullptr, -1, false, nullptr, nullptr},\n};\ninline constexpr std::size_t base_count = (sizeof(bases) / sizeof(bases[0])) - 1;\ninline constexpr VTableLayout vtables[] = {\n");
    for vtable in &db.vtables {
        let name = cpp_string(
            vtable
                .get("demangled")
                .or_else(|| vtable.get("class_name"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        let rva = vtable
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let slots = vtable
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        let evidence = cpp_string(
            vtable
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
        );
        let confidence = cpp_string(
            vtable
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("pdb-derived"),
        );
        out.push_str(&format!(
            "    {{\"{name}\", 0x{rva:X}U, {slots}U, \"{evidence}\", \"{confidence}\"}},\n"
        ));
    }
    out.push_str("    {nullptr, 0, 0, nullptr, nullptr},\n};\ninline constexpr std::size_t vtable_count = (sizeof(vtables) / sizeof(vtables[0])) - 1;\ninline constexpr VTableSlotLayout vtable_slots[] = {\n");
    for vtable in &db.vtables {
        let table_rva = vtable
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        for entry in vtable
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let slot = entry
                .get("slot")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let target_rva = entry
                .get("target_rva")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let id = entry
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .map_or("nullptr".to_string(), |s| format!("\"{}\"", cpp_string(s)));
            let name = entry
                .get("target_name")
                .and_then(serde_json::Value::as_str)
                .map_or("nullptr".to_string(), |s| format!("\"{}\"", cpp_string(s)));
            let ambiguous = entry
                .get("target_ambiguous")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let adjustment = entry
                .get("this_adjustment")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            out.push_str(&format!(
                "    {{0x{table_rva:X}U, {slot}U, 0x{target_rva:X}U, {id}, {name}, {ambiguous}, {adjustment}}},\n"
            ));
        }
    }
    out.push_str("    {0, 0, 0, nullptr, nullptr, true, 0},\n};\ninline constexpr std::size_t vtable_slot_count = (sizeof(vtable_slots) / sizeof(vtable_slots[0])) - 1;\n}\n");
    out
}

fn cpp_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn vcall_header(db: &Database) -> String {
    let mut out = String::from(
        "// Windissect signature-verified virtual-slot helpers — DO NOT EDIT.\n\
         #pragma once\n#include <cstdint>\n\n\
         #if defined(_M_IX86) || defined(__i386__)\n\
         #error \"Windissect typed vcalls currently require the Windows x64 ABI\"\n\
         #endif\n\nnamespace windissect_vcalls {\n",
    );
    let symbols: BTreeMap<&str, &Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let mut used = BTreeSet::new();
    for table in &db.vtables {
        let table_rva = table
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let owner = table
            .get("demangled")
            .and_then(serde_json::Value::as_str)
            .and_then(vftable_owner)
            .map(sanitize_filename)
            .unwrap_or_else(|| "unknown".to_string());
        for entry in table
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let ambiguous = entry
                .get("target_ambiguous")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let compatible = entry
                .get("signature_compatible")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if ambiguous && !compatible {
                continue;
            }
            let Some(id) = entry
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .or_else(|| {
                    entry
                        .get("signature_source_id")
                        .and_then(serde_json::Value::as_str)
                })
            else {
                continue;
            };
            let Some(symbol) = symbols.get(id).copied().filter(|s| s.sig.parse_ok) else {
                continue;
            };
            let Some(ret) = cpp_abi_type(symbol.sig.ret.as_ref()) else {
                continue;
            };
            let Some(params) = symbol
                .sig
                .params
                .iter()
                .map(|ty| cpp_abi_type(Some(ty)))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let slot = entry
                .get("slot")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0);
            let target_rva = entry
                .get("target_rva")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0);
            if !db.vtable_slot_is_verified(table_rva, slot, target_rva)
                || !db.symbol_is_verified_callable(&symbol.id)
            {
                continue;
            }
            let method = if ambiguous {
                "abi_equivalent".to_string()
            } else {
                sanitize_filename(symbol.sig.method.as_deref().unwrap_or("virtual"))
            };
            let mut function = format!("{owner}_vslot_{slot}_{method}");
            let base = function.clone();
            let mut suffix = 2;
            while !used.insert(function.clone()) {
                function = format!("{base}_{suffix}");
                suffix += 1;
            }
            let this_ty = if symbol.sig.is_const {
                "const void*"
            } else {
                "void*"
            };
            let declarations = params
                .iter()
                .enumerate()
                .map(|(index, ty)| format!("{ty} p{index}"))
                .collect::<Vec<_>>();
            let arguments = (0..params.len())
                .map(|index| format!("p{index}"))
                .collect::<Vec<_>>();
            let fn_types = std::iter::once(this_ty.to_string())
                .chain(params.iter().cloned())
                .collect::<Vec<_>>()
                .join(", ");
            let fn_args = std::iter::once("self".to_string())
                .chain(arguments)
                .collect::<Vec<_>>()
                .join(", ");
            let declaration_tail = if declarations.is_empty() {
                String::new()
            } else {
                format!(", {}", declarations.join(", "))
            };
            let nodiscard = if ret == "void" { "" } else { "[[nodiscard]] " };
            out.push_str(&format!(
                "\n// Slot {slot}; identity_ambiguous={ambiguous}; ABI-equivalent={compatible}.\n{nodiscard}inline {ret} {function}({this_ty} self{declaration_tail}) {{\n    using Fn = {ret} (*)({fn_types});\n    auto table = *reinterpret_cast<const void* const* const*>(self);\n    auto function_ptr = reinterpret_cast<Fn>(const_cast<void*>(table[{slot}]));\n"
            ));
            if ret == "void" {
                out.push_str(&format!("    function_ptr({fn_args});\n}}\n"));
            } else {
                out.push_str(&format!("    return function_ptr({fn_args});\n}}\n"));
            }
        }
    }
    out.push_str("\n} // namespace windissect_vcalls\n");
    out
}

fn vftable_owner(name: &str) -> Option<&str> {
    let prefix = name.strip_prefix("const ")?;
    Some(&prefix[..prefix.find("::`vftable'")?])
}

fn cpp_abi_type(ty: Option<&TypeText>) -> Option<String> {
    let Some(ty) = ty else {
        return Some("void".to_string());
    };
    let text = ty.text.trim();
    if text.contains('*') || text.contains('&') {
        return Some(if text.contains("const") {
            "const void*".to_string()
        } else {
            "void*".to_string()
        });
    }
    Some(
        match text {
            "void" => "void",
            "bool" => "bool",
            "char" | "signed char" => "std::int8_t",
            "unsigned char" => "std::uint8_t",
            "short" | "__int16" => "std::int16_t",
            "unsigned short" | "wchar_t" | "__wchar_t" => "std::uint16_t",
            "int" | "long" | "__int32" | "signed long" | "signed int" => "std::int32_t",
            "unsigned" | "unsigned int" | "unsigned long" => "std::uint32_t",
            "__int64" | "long long" | "signed long long" => "std::int64_t",
            "unsigned __int64" | "unsigned long long" => "std::uint64_t",
            "float" => "float",
            "double" => "double",
            _ => return None,
        }
        .to_string(),
    )
}

fn direct_call_header(db: &Database) -> String {
    let dll_wide = db
        .binary
        .file
        .encode_utf16()
        .chain(std::iter::once(0))
        .map(|value| format!("0x{value:04X}"))
        .collect::<Vec<_>>()
        .join(", ");
    let dll_wide_len = db.binary.file.encode_utf16().count() + 1;
    let timestamp = db
        .binary
        .timestamp
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let mut out = String::from(
        "// Windissect exact-build RVA call helpers — DO NOT EDIT.\n\
         // Configure set_resolver() with a loader that validates the expected build.\n\
         #pragma once\n#include <cstddef>\n#include <cstdint>\n#include <cstdlib>\n\n\
         #if defined(_M_IX86) || defined(__i386__)\n\
         #error \"Windissect typed direct calls currently require the Windows x64 ABI\"\n\
         #endif\n\nnamespace windissect_calls {\n\
         using ResolveRva = const void* (*)(std::uint32_t);\n\
         __DEFAULT_RESOLVER__\n\
         inline void set_resolver(ResolveRva value) noexcept { resolver = value; }\n\
         [[nodiscard]] inline const void* require(std::uint32_t rva) {\n\
             if (resolver == nullptr) std::abort();\n\
             const void* address = resolver(rva);\n\
             if (address == nullptr) std::abort();\n\
             return address;\n\
         }\n",
    );
    let windows_resolver = format!(
        "#if defined(_WIN32)\n\
         extern \"C\" __declspec(dllimport) void* __stdcall GetModuleHandleW(const wchar_t*);\n\
         [[nodiscard]] inline const void* default_resolver(std::uint32_t rva) {{\n\
             static constexpr wchar_t module_name[{dll_wide_len}] = {{{dll_wide}}};\n\
             const auto base = static_cast<const std::uint8_t*>(GetModuleHandleW(module_name));\n\
             if (base == nullptr) return nullptr;\n\
             const auto pe = *reinterpret_cast<const std::uint32_t*>(base + 0x3c);\n\
             const auto live_timestamp = *reinterpret_cast<const std::uint32_t*>(base + pe + 8);\n\
             const auto image_size = *reinterpret_cast<const std::uint32_t*>(base + pe + 80);\n\
             if (live_timestamp != {timestamp}U || rva >= image_size) return nullptr;\n\
             return base + rva;\n\
         }}\n\
         inline ResolveRva resolver = default_resolver;\n\
         #else\n\
         inline ResolveRva resolver = nullptr;\n\
         #endif"
    );
    out = out.replace("__DEFAULT_RESOLVER__", &windows_resolver);
    let mut used = BTreeSet::new();
    for symbol in &db.symbols {
        if !db.symbol_is_verified_callable(&symbol.id)
            || symbol.library
            || !symbol.is_code
            || !symbol.sig.parse_ok
            || matches!(
                symbol.kind,
                Kind::Ctor | Kind::Dtor | Kind::Thunk | Kind::Data
            )
        {
            continue;
        }
        let Some(ret) = cpp_abi_type(symbol.sig.ret.as_ref()) else {
            continue;
        };
        let Some(params) = symbol
            .sig
            .params
            .iter()
            .map(|ty| cpp_abi_type(Some(ty)))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let has_this =
            symbol.sig.class.is_some() && symbol.sig.storage.as_deref() != Some("static");
        let this_ty = if symbol.sig.is_const {
            "const void*"
        } else {
            "void*"
        };
        let base = sanitize_filename(&format!(
            "{}_{}",
            symbol.sig.class.as_deref().unwrap_or("global"),
            symbol.sig.method.as_deref().unwrap_or("call")
        ));
        let mut function = base.clone();
        let mut suffix = 2;
        while !used.insert(function.clone()) {
            function = format!("{base}_{suffix}");
            suffix += 1;
        }
        let mut declarations = Vec::new();
        let mut types = Vec::new();
        let mut arguments = Vec::new();
        if has_this {
            declarations.push(format!("{this_ty} self"));
            types.push(this_ty.to_string());
            arguments.push("self".to_string());
        }
        for (index, ty) in params.iter().enumerate() {
            declarations.push(format!("{ty} p{index}"));
            types.push(ty.clone());
            arguments.push(format!("p{index}"));
        }
        let nodiscard = if ret == "void" { "" } else { "[[nodiscard]] " };
        out.push_str(&format!(
            "\n// RVA 0x{:X}; {}; {}.\n{nodiscard}inline {ret} {function}({}) {{\n    using Fn = {ret} (*)({});\n    auto target = reinterpret_cast<Fn>(const_cast<void*>(require(0x{:X}U)));\n",
            symbol.rva,
            cpp_string(&symbol.mangled),
            if symbol.exported { "PE export" } else { "PDB internal" },
            declarations.join(", "),
            types.join(", "),
            symbol.rva,
        ));
        if ret == "void" {
            out.push_str(&format!("    target({});\n}}\n", arguments.join(", ")));
        } else {
            out.push_str(&format!(
                "    return target({});\n}}\n",
                arguments.join(", ")
            ));
        }
    }
    out.push_str("\n} // namespace windissect_calls\n");
    out
}
