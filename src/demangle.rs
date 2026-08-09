//! Demangles MSVC C++ mangled symbols and classifies signatures. See `docs/codebase.md#4-demanglers--typeparsers` or `cargo doc`.

use crate::model::{Kind, Signature, Symbol};
use crate::typeparse::{self, split_sep_top, split_top, type_text};
use msvc_demangler::DemangleFlags;

const CALLCONVS: &[&str] = &[
    "__cdecl",
    "__thiscall",
    "__stdcall",
    "__fastcall",
    "__vectorcall",
    "__clrcall",
];

/// Demangle one MSVC name to a full declaration; None if not a valid mangling.
pub fn demangle(mangled: &str) -> Option<String> {
    let flags = DemangleFlags::COMPLETE | DemangleFlags::SPACE_AFTER_COMMA;
    msvc_demangler::demangle(mangled, flags).ok()
}

/// Structure a demangled declaration; `parse_ok=false` if not fully split.
pub fn parse_decl(decl: &str) -> Signature {
    let mut sig = Signature::default();
    let mut s = decl.trim();
    if s.is_empty() {
        return sig;
    }

    // Access specifier.
    for a in ["public", "protected", "private"] {
        let pfx = format!("{a}: ");
        if let Some(rest) = s.strip_prefix(&pfx) {
            sig.access = Some(a.to_string());
            s = rest;
            break;
        }
    }
    // Storage class.
    if let Some(rest) = s.strip_prefix("virtual ") {
        sig.storage = Some("virtual".into());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("static ") {
        sig.storage = Some("static".into());
        s = rest;
    }

    // Parameter list = the last top-level (...); optional trailing " const".
    let Some((open, close)) = typeparse::last_top_parens(s) else {
        return sig; // not a function decl (data/vftable/RTTI)
    };
    let head = s[..open].trim();
    let params = &s[open + 1..close];
    match s[close + 1..].trim() {
        "" => {}
        "const" => sig.is_const = true,
        _ => return sig, // unexpected trailing text — don't guess
    }

    // Split head into "<ret> <callconv> <qualified-name>".
    let Some((cc_idx, cc)) = typeparse::top_token(head, CALLCONVS) else {
        return sig; // no calling convention — flat C export / data
    };
    sig.callconv = Some(cc.to_string());
    let ret = head[..cc_idx].trim();
    if !ret.is_empty() {
        sig.ret = Some(type_text(ret));
    }
    let qual = head[cc_idx + cc.len()..].trim();

    // Qualified name -> namespace / class / method (top-level "::" split).
    let parts = split_sep_top(qual, "::");
    match parts.len() {
        0 => return sig,
        1 => sig.method = Some(parts[0].to_string()),
        n => {
            sig.method = Some(parts[n - 1].to_string());
            sig.class = Some(parts[n - 2].to_string());
            if n > 2 {
                sig.namespace = Some(parts[..n - 2].join("::"));
            }
        }
    }

    // Parameters (top-level comma split; "void" = none).
    let p = params.trim();
    if !p.is_empty() && p != "void" {
        sig.params = split_top(params, ',').into_iter().map(type_text).collect();
    }

    sig.parse_ok = true;
    sig
}

/// Assign a shape by name and structure.
pub fn classify(s: &Symbol) -> Kind {
    // Non-function special names appear in the export table too.
    let m = &s.mangled;
    if m.starts_with("??_7") || m.starts_with("??_R") || m.starts_with("??_C") {
        return Kind::Operator; // vftable / RTTI / string literal (not a function)
    }
    // Flat C export: never mangled, so no signature — but the name is known.
    if !m.starts_with('?') {
        return Kind::CFunc;
    }
    if !s.sig.parse_ok {
        // Demangled but no param list => static data member (Schema::*Property).
        return if s.demangled.is_some() {
            Kind::Data
        } else {
            Kind::Unknown
        };
    }

    let name = s.sig.method.as_deref().unwrap_or("");
    let class = s.sig.class.as_deref().unwrap_or("");
    if name.starts_with('~')
        || m.starts_with("??1")
        || m.starts_with("??_G")
        || m.starts_with("??_E")
    {
        Kind::Dtor
    } else if (!class.is_empty() && name == class) || m.starts_with("??0") {
        Kind::Ctor
    } else if matches!(name, "AddRef" | "Release" | "QueryInterface") {
        Kind::Refcount
    } else if name.contains("operator") {
        Kind::Operator
    } else if is_accessor(name) {
        Kind::Accessor
    } else if class.is_empty() {
        Kind::CFunc
    } else {
        Kind::Method
    }
}

fn is_accessor(name: &str) -> bool {
    if name.ends_with("Prop") {
        return true;
    }
    for p in ["Get", "Set", "Is", "Has"] {
        if let Some(rest) = name.strip_prefix(p)
            && rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        {
            return true;
        }
    }
    false
}
