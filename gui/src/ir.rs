//! Loads what the window shows from an IR file and shapes it into tables.
//! IR can run to gigabytes; anything not declared here (instruction streams,
//! CFG edges, evidence bodies) is skipped by the parser without being kept.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

#[derive(Default, Deserialize)]
pub struct Binary {
    pub pdb_name: Option<String>,
    pub pdb_guid: Option<String>,
    pub machine: Option<String>,
    pub image_size: Option<u64>,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Deserialize)]
struct Symbol {
    id: Option<String>,
    demangled: Option<String>,
    mangled: Option<String>,
    rva: Option<u64>,
    size: Option<u64>,
    kind: Option<String>,
    provenance: Option<String>,
    confidence: Option<String>,
    exported: Option<bool>,
    sig: Option<Signature>,
}

#[derive(Deserialize)]
struct TypeText {
    text: Option<String>,
}

#[derive(Deserialize)]
struct Signature {
    access: Option<String>,
    storage: Option<String>,
    callconv: Option<String>,
    ret: Option<TypeText>,
    class: Option<String>,
    method: Option<String>,
    namespace: Option<String>,
    #[serde(default)]
    params: Vec<TypeText>,
    #[serde(default)]
    is_const: bool,
}

#[derive(Deserialize)]
struct Function {
    rva: Option<u64>,
    size: Option<u64>,
    #[serde(default)]
    symbol_ids: Vec<String>,
}

#[derive(Deserialize)]
struct Observation {
    offset: Option<u64>,
    width: Option<u64>,
    access: Option<String>,
    confidence: Option<String>,
    evidence_symbol: Option<String>,
}

#[derive(Deserialize)]
struct Layout {
    name: Option<String>,
    kind: Option<String>,
    complete_layout: Option<bool>,
    source: Option<String>,
    note: Option<String>,
    #[serde(default)]
    observations: Vec<Observation>,
}

#[derive(Deserialize)]
struct Candidate {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Slot {
    slot: Option<u64>,
    target_id: Option<String>,
    #[serde(default)]
    target_candidates: Vec<Candidate>,
    #[serde(default)]
    target_ambiguous: bool,
    #[serde(default)]
    is_thunk: bool,
}

#[derive(Deserialize)]
struct VTable {
    demangled: Option<String>,
    mangled: Option<String>,
    rva: Option<u64>,
    confidence: Option<String>,
    #[serde(default)]
    entries: Vec<Slot>,
}

#[derive(Deserialize)]
struct Claim {
    id: Option<String>,
    status: Option<String>,
    usability: Option<String>,
    subject: Option<Value>,
    proof_id: Option<String>,
}

#[derive(Deserialize)]
struct Conflict {
    id: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    resolved: bool,
    #[serde(default)]
    claim_ids: Vec<String>,
}

#[derive(Deserialize)]
struct IrFile {
    #[serde(default)]
    binary: Binary,
    #[serde(default)]
    symbols: Vec<Symbol>,
    #[serde(default)]
    functions: Vec<Function>,
    #[serde(default)]
    types: Vec<Layout>,
    #[serde(default)]
    vtables: Vec<VTable>,
    #[serde(default)]
    classes: Vec<Value>,
    #[serde(default)]
    enums: Vec<Value>,
    #[serde(default)]
    claims: Vec<Claim>,
    #[serde(default)]
    conflicts: Vec<Conflict>,
}

/// How much a row can be trusted, shown as a coloured dot.
#[derive(Clone, Copy, PartialEq)]
pub enum Tone {
    Good,
    Neutral,
    Weak,
    Bad,
}

/// One block of the inspector.
pub enum Detail {
    /// A short property: label on the left, value on the right.
    Prop(String, String),
    /// A long or code-like value under its label.
    Code(String, String),
    /// Like Code, but only its first line shows until expanded.
    Fold(String, String),
    /// A list of records, e.g. a layout's fields or a vtable's slots. Each row
    /// may carry a dim second line (`notes`), such as the mangled source.
    Table {
        title: String,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
        notes: Vec<String>,
        total: usize,
    },
}

pub struct Row {
    pub name: String,
    /// Inspector heading when the name is long, e.g. the method alone.
    pub title: Option<String>,
    /// Shown under the heading, e.g. the class.
    pub subtitle: Option<String>,
    /// Extra text search also matches (the full declaration).
    pub search: String,
    pub cols: [String; 3],
    pub tone: Tone,
    pub detail: Vec<Detail>,
}

pub struct Table {
    pub title: &'static str,
    pub description: &'static str,
    pub headers: [&'static str; 3],
    /// Column widths; 0 hides a column.
    pub widths: [f32; 3],
    pub empty: &'static str,
    pub rows: Vec<Row>,
}

pub struct Summary {
    pub binary: Binary,
    pub tables: Vec<Table>,
}

const MAX_SUBROWS: usize = 256;

fn hex(v: Option<u64>) -> String {
    v.map(|v| format!("0x{v:08X}")).unwrap_or_default()
}

fn text(v: &Option<String>) -> String {
    v.clone().unwrap_or_default()
}

fn props(items: Vec<(&'static str, String)>) -> Vec<Detail> {
    items
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| Detail::Prop(k.to_string(), v))
        .collect()
}

fn tone_of(confidence: Option<&str>) -> Tone {
    match confidence {
        Some("certain" | "verified" | "proven") => Tone::Good,
        Some("likely" | "corroborated") => Tone::Neutral,
        Some("candidate" | "possible" | "low") => Tone::Weak,
        _ => Tone::Neutral,
    }
}

fn compact(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}: {}", compact(v)))
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

/// The readable form of a symbol id, falling back to the id itself.
fn readable<'a>(names: &HashMap<&str, &'a str>, id: &'a str) -> &'a str {
    names.get(id).copied().unwrap_or(id)
}

/// `ret Class<T>::Method(args) const` -> `Method`. Template arguments and
/// parameter lists can themselves hold spaces, `::` and parentheses, so
/// separators only count outside every `<...>` and `(...)`.
fn short_name(full: &str) -> String {
    let s = full.trim();
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    // The parameter list is the last top-level parenthesised group.
    let (mut angle, mut paren) = (0i32, 0i32);
    let mut params_at = None;
    for &(i, c) in &chars {
        match c {
            '<' => angle += 1,
            '>' => angle = (angle - 1).max(0),
            '(' => {
                if angle == 0 && paren == 0 {
                    params_at = Some(i);
                }
                paren += 1;
            }
            ')' => paren = (paren - 1).max(0),
            _ => {}
        }
    }
    let head = &s[..params_at.unwrap_or(s.len())];
    // The name starts after the last top-level `::` or space.
    // MSVC quotes special names: `vector deleting destructor'.
    let (mut angle, mut paren, mut quote) = (0i32, 0i32, 0i32);
    let mut start = 0;
    let bytes = head.as_bytes();
    for (i, c) in head.char_indices() {
        let top = angle == 0 && paren == 0 && quote == 0;
        match c {
            '`' => quote += 1,
            '\'' if quote > 0 => quote -= 1,
            '<' if quote == 0 => angle += 1,
            '>' if quote == 0 => angle = (angle - 1).max(0),
            '(' if quote == 0 => paren += 1,
            ')' if quote == 0 => paren = (paren - 1).max(0),
            ':' if top && bytes.get(i + 1) == Some(&b':') => start = i + 2,
            ' ' if top => start = i + 1,
            _ => {}
        }
    }
    let name = head[start.min(head.len())..].trim();
    if name.is_empty() {
        head.trim().to_string()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::short_name;

    #[test]
    fn collapses_only_long_template_arguments() {
        use super::collapse_templates;
        assert_eq!(
            collapse_templates("struct _tlgWrapperByVal<4> const &"),
            "struct _tlgWrapperByVal<4> const &"
        );
        assert_eq!(
            collapse_templates("A<struct B<int>, class C<long>>::f<int>"),
            "A<\u{2026}>::f<int>"
        );
        assert_eq!(collapse_templates("plain"), "plain");
    }

    #[test]
    fn short_names_survive_templates_and_parameters() {
        assert_eq!(
            short_name("public: long __cdecl BUXButtonCollection::ShowNextPage(void)"),
            "ShowNextPage"
        );
        assert_eq!(
            short_name(
                "public: virtual void * __cdecl wistd::__function::__func<class <lambda_8d>, bool __cdecl (void *, unsigned int)>::`vector deleting destructor'(unsigned int)"
            ),
            "`vector deleting destructor'"
        );
        assert_eq!(
            short_name("protected: long __cdecl A<int, B<C> >::Get(struct X *) const"),
            "Get"
        );
        assert_eq!(short_name("_tlgEnableCallback"), "_tlgEnableCallback");
    }
}

/// Long template arguments collapsed to `<…>`, short ones kept:
/// `A<B<C>, D>::f<int>` -> `A<…>::f<int>`.
pub fn collapse_templates(text: &str) -> String {
    const KEEP: usize = 12;
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '<' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // Find the matching '>'.
        let mut depth = 0usize;
        let mut end = chars.len();
        for (j, c) in chars.iter().enumerate().skip(i) {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = end.saturating_sub(i + 1);
        if inner <= KEEP && end < chars.len() {
            out.extend(&chars[i..=end]);
        } else {
            out.push_str("<\u{2026}>");
        }
        i = end + 1;
    }
    out
}

/// The declaration laid out like source: one parameter per line.
fn pretty_declaration(sig: &Signature, fallback: &str) -> String {
    let mut head = Vec::new();
    for part in [&sig.access, &sig.storage] {
        if let Some(p) = part {
            head.push(p.trim_end_matches(':').to_string());
        }
    }
    if let Some(ret) = sig.ret.as_ref().and_then(|r| r.text.clone()) {
        head.push(ret);
    }
    if let Some(cc) = &sig.callconv {
        head.push(cc.clone());
    }
    let owner = sig.class.clone().or_else(|| sig.namespace.clone());
    let Some(method) = &sig.method else {
        return fallback.to_string();
    };
    let qualified = match owner {
        Some(o) => format!("{o}::{method}"),
        None => method.clone(),
    };
    let params = if sig.params.is_empty() {
        "()".to_string()
    } else {
        let list: Vec<String> = sig
            .params
            .iter()
            .map(|p| format!("    {}", p.text.clone().unwrap_or_default()))
            .collect();
        format!("(\n{}\n)", list.join(",\n"))
    };
    let mut text = String::new();
    if !head.is_empty() {
        text.push_str(&head.join(" "));
        text.push('\n');
    }
    text.push_str(&qualified);
    text.push_str(&params);
    if sig.is_const {
        text.push_str(" const");
    }
    text
}

fn symbols_table(symbols: &[Symbol]) -> Table {
    let rows = symbols
        .iter()
        .map(|s| {
            let full = s
                .demangled
                .clone()
                .or_else(|| s.mangled.clone())
                .or_else(|| s.id.clone())
                .unwrap_or_else(|| "?".into());
            let sig = s.sig.as_ref().filter(|g| g.method.is_some());
            // List and heading: `Class<…>::Method<…>` reads; the declaration does not.
            let (name, title, subtitle) = match sig {
                Some(g) => {
                    let method = collapse_templates(g.method.as_deref().unwrap_or_default());
                    let owner = g
                        .class
                        .as_deref()
                        .or(g.namespace.as_deref())
                        .map(collapse_templates);
                    let name = match &owner {
                        Some(o) => format!("{o}::{method}"),
                        None => method.clone(),
                    };
                    (name, Some(method), owner)
                }
                None => (full.clone(), None, None),
            };
            let mut detail = props(vec![
                ("Kind", text(&s.kind)),
                ("RVA", hex(s.rva)),
                (
                    "Size",
                    s.size.map(|v| format!("{v} bytes")).unwrap_or_default(),
                ),
                ("Source", text(&s.provenance)),
                ("Confidence", text(&s.confidence)),
                (
                    "Exported",
                    s.exported
                        .map(|e| if e { "yes" } else { "no" }.to_string())
                        .unwrap_or_default(),
                ),
            ]);
            if let Some(g) = sig {
                detail.extend(props(vec![
                    (
                        "Access",
                        g.access
                            .clone()
                            .map(|a| a.trim_end_matches(':').to_string())
                            .unwrap_or_default(),
                    ),
                    ("Storage", text(&g.storage)),
                    ("Calling conv", text(&g.callconv)),
                    (
                        "Returns",
                        g.ret
                            .as_ref()
                            .and_then(|r| r.text.as_deref())
                            .map(collapse_templates)
                            .unwrap_or_default(),
                    ),
                    (
                        "Namespace",
                        g.namespace
                            .as_deref()
                            .map(collapse_templates)
                            .unwrap_or_default(),
                    ),
                    (
                        "Const",
                        if g.is_const {
                            "yes".into()
                        } else {
                            String::new()
                        },
                    ),
                ]));
                if !g.params.is_empty() {
                    let types: Vec<String> = g
                        .params
                        .iter()
                        .map(|p| p.text.clone().unwrap_or_default())
                        .collect();
                    detail.push(Detail::Table {
                        title: "Parameters".into(),
                        headers: vec!["#".into(), "type".into()],
                        rows: types
                            .iter()
                            .enumerate()
                            .map(|(i, t)| vec![i.to_string(), collapse_templates(t)])
                            .collect(),
                        notes: types
                            .iter()
                            .map(|t| {
                                if collapse_templates(t) != *t {
                                    t.clone()
                                } else {
                                    String::new()
                                }
                            })
                            .collect(),
                        total: types.len(),
                    });
                }
                detail.push(Detail::Fold(
                    "Declaration".into(),
                    pretty_declaration(g, &full),
                ));
            } else if s.demangled.is_some() {
                detail.push(Detail::Fold("Declaration".into(), full.clone()));
            }
            if let Some(m) = &s.mangled {
                detail.push(Detail::Fold("Mangled".into(), m.clone()));
            }
            Row {
                search: full,
                name,
                title,
                subtitle,
                cols: [text(&s.kind), text(&s.provenance), hex(s.rva)],
                tone: tone_of(s.confidence.as_deref()),
                detail,
            }
        })
        .collect();
    Table {
        title: "Symbols",
        description: "Every named address: exports, and with a PDB, internal functions, methods and data.",
        headers: ["kind", "source", "rva"],
        widths: [90., 70., 92.],
        empty: "No symbols were recovered.",
        rows,
    }
}

fn functions_table(functions: &[Function], names: &HashMap<&str, &str>) -> Table {
    let rows = functions
        .iter()
        .map(|f| {
            let all: Vec<&str> = f.symbol_ids.iter().map(|id| readable(names, id)).collect();
            let name = all
                .first()
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("sub_{:X}", f.rva.unwrap_or(0)));
            let mut detail = props(vec![
                ("RVA", hex(f.rva)),
                (
                    "Size",
                    f.size.map(|v| format!("{v} bytes")).unwrap_or_default(),
                ),
                ("Names", f.symbol_ids.len().to_string()),
            ]);
            if all.len() > 1 {
                detail.push(Detail::Table {
                    title: "Same code, other names".into(),
                    headers: vec!["name".into()],
                    rows: all[1..]
                        .iter()
                        .take(MAX_SUBROWS)
                        .map(|n| vec![short_name(n)])
                        .collect(),
                    notes: all[1..]
                        .iter()
                        .take(MAX_SUBROWS)
                        .map(|n| n.to_string())
                        .collect(),
                    total: all.len() - 1,
                });
            }
            Row {
                title: None,
                subtitle: None,
                search: String::new(),
                name,
                cols: [
                    f.size.map(|v| v.to_string()).unwrap_or_default(),
                    match f.symbol_ids.len() {
                        0 => "unnamed".into(),
                        1 => String::new(),
                        n => format!("{n} names"),
                    },
                    hex(f.rva),
                ],
                tone: if f.symbol_ids.is_empty() {
                    Tone::Weak
                } else {
                    Tone::Good
                },
                detail,
            }
        })
        .collect();
    Table {
        title: "Functions",
        description: "Recovered function bodies, by address. Identical code shared by several names is listed once.",
        headers: ["bytes", "aliases", "rva"],
        widths: [60., 70., 92.],
        empty: "No function boundaries were recovered.",
        rows,
    }
}

fn types_table(types: &[Layout], names: &HashMap<&str, &str>) -> Table {
    let rows = types
        .iter()
        .map(|t| {
            let mut fields: Vec<&Observation> = t.observations.iter().collect();
            fields.sort_by_key(|o| (o.offset.unwrap_or(0), o.width.unwrap_or(0)));
            let distinct = {
                let mut offsets: Vec<u64> = fields.iter().filter_map(|o| o.offset).collect();
                offsets.dedup();
                offsets.len()
            };
            let complete = t.complete_layout == Some(true);
            let mut detail = props(vec![
                (
                    "Layout",
                    if complete {
                        "complete".into()
                    } else {
                        "partial".into()
                    },
                ),
                ("Offsets", distinct.to_string()),
                ("Observations", t.observations.len().to_string()),
                ("Source", text(&t.source)),
                ("Kind", text(&t.kind)),
            ]);
            if let Some(note) = &t.note {
                detail.push(Detail::Code("Note".into(), note.clone()));
            }
            if !fields.is_empty() {
                detail.push(Detail::Table {
                    title: "Observed fields".into(),
                    headers: vec![
                        "offset".into(),
                        "size".into(),
                        "access".into(),
                        "trust".into(),
                        "seen in".into(),
                    ],
                    rows: fields
                        .iter()
                        .take(MAX_SUBROWS)
                        .map(|o| {
                            let source = o
                                .evidence_symbol
                                .as_deref()
                                .map(|id| short_name(readable(names, id)));
                            vec![
                                format!("+0x{:X}", o.offset.unwrap_or(0)),
                                format!("{}B", o.width.unwrap_or(0)),
                                text(&o.access),
                                text(&o.confidence),
                                source.unwrap_or_default(),
                            ]
                        })
                        .collect(),
                    notes: fields
                        .iter()
                        .take(MAX_SUBROWS)
                        .map(|o| {
                            o.evidence_symbol
                                .as_deref()
                                .map(|id| readable(names, id).to_string())
                                .unwrap_or_default()
                        })
                        .collect(),
                    total: fields.len(),
                });
            }
            Row {
                title: None,
                subtitle: None,
                search: String::new(),
                name: text(&t.name),
                cols: [
                    if distinct == 0 {
                        "none".into()
                    } else {
                        distinct.to_string()
                    },
                    if complete {
                        "complete".into()
                    } else {
                        "partial".into()
                    },
                    String::new(),
                ],
                tone: if complete {
                    Tone::Good
                } else if distinct == 0 {
                    Tone::Weak
                } else {
                    Tone::Neutral
                },
                detail,
            }
        })
        .collect();
    Table {
        title: "Types",
        description: "Object layouts inferred from how code uses `this`: proven offsets and widths, never guessed sizes.",
        headers: ["offsets", "layout", ""],
        widths: [70., 80., 0.],
        empty: "No type layouts were recovered.",
        rows,
    }
}

/// Full names a slot may point to: its target, or every candidate when
/// identical code makes it ambiguous.
fn slot_names(e: &Slot, names: &HashMap<&str, &str>) -> Vec<String> {
    if let Some(id) = &e.target_id {
        return vec![readable(names, id).to_string()];
    }
    e.target_candidates
        .iter()
        .filter_map(|c| {
            c.name
                .clone()
                .or_else(|| c.id.as_deref().map(|id| readable(names, id).to_string()))
        })
        .collect()
}

fn slot_target(e: &Slot, names: &HashMap<&str, &str>) -> String {
    let all = slot_names(e, names);
    match all.len() {
        0 => "unknown".into(),
        1 => short_name(&all[0]),
        n => format!("{} +{}", short_name(&all[0]), n - 1),
    }
}

fn slot_note(e: &Slot, names: &HashMap<&str, &str>) -> String {
    slot_names(e, names).join("\n")
}

fn vtables_table(vtables: &[VTable], names: &HashMap<&str, &str>) -> Table {
    let rows = vtables
        .iter()
        .map(|v| {
            let ambiguous = v.entries.iter().filter(|e| e.target_ambiguous).count();
            let mut detail = props(vec![
                ("RVA", hex(v.rva)),
                ("Slots", v.entries.len().to_string()),
                ("Ambiguous", ambiguous.to_string()),
                ("Confidence", text(&v.confidence)),
            ]);
            if let Some(m) = &v.mangled {
                detail.push(Detail::Code("Mangled".into(), m.clone()));
            }
            if !v.entries.is_empty() {
                detail.push(Detail::Table {
                    title: "Slots".into(),
                    headers: vec!["#".into(), "flags".into(), "target".into()],
                    rows: v
                        .entries
                        .iter()
                        .take(MAX_SUBROWS)
                        .map(|e| {
                            let target = slot_target(e, names);
                            let flags = match (e.target_ambiguous, e.is_thunk) {
                                (true, true) => "ambig thunk",
                                (true, false) => "ambig",
                                (false, true) => "thunk",
                                _ => "",
                            };
                            vec![e.slot.unwrap_or(0).to_string(), flags.to_string(), target]
                        })
                        .collect(),
                    notes: v
                        .entries
                        .iter()
                        .take(MAX_SUBROWS)
                        .map(|e| slot_note(e, names))
                        .collect(),
                    total: v.entries.len(),
                });
            }
            Row {
                title: None,
                subtitle: None,
                search: String::new(),
                name: v
                    .demangled
                    .clone()
                    .or_else(|| v.mangled.clone())
                    .unwrap_or_default(),
                cols: [
                    v.entries.len().to_string(),
                    if ambiguous > 0 {
                        format!("{ambiguous} ambiguous")
                    } else {
                        "exact".into()
                    },
                    hex(v.rva),
                ],
                tone: if ambiguous > 0 {
                    Tone::Weak
                } else {
                    tone_of(v.confidence.as_deref())
                },
                detail,
            }
        })
        .collect();
    Table {
        title: "VTables",
        description: "Virtual function tables and what each slot points to. Ambiguous slots share identical code.",
        headers: ["slots", "targets", "rva"],
        widths: [50., 100., 92.],
        empty: "No vtables were recovered.",
        rows,
    }
}

/// Classes and enums vary by producer, so they are shown field by field.
fn generic_table(
    title: &'static str,
    description: &'static str,
    empty: &'static str,
    records: &[Value],
) -> Table {
    let rows = records
        .iter()
        .map(|r| {
            let name = r
                .get("qualified_name")
                .or_else(|| r.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            let count_of = |key: &str| r.get(key).and_then(Value::as_array).map(Vec::len);
            let first = count_of("values")
                .map(|n| format!("{n} values"))
                .or_else(|| count_of("members").map(|n| format!("{n} members")))
                .or_else(|| r.get("property_count").map(|n| format!("{n} props")))
                .unwrap_or_default();
            let mut detail = Vec::new();
            if let Some(map) = r.as_object() {
                for (key, value) in map {
                    if key == "name" || key == "qualified_name" {
                        continue;
                    }
                    let label = key.replace('_', " ");
                    match value {
                        Value::Array(items)
                            if items.iter().all(Value::is_object) && !items.is_empty() =>
                        {
                            let headers: Vec<String> = items[0]
                                .as_object()
                                .map(|o| o.keys().take(4).cloned().collect())
                                .unwrap_or_default();
                            detail.push(Detail::Table {
                                title: label,
                                rows: items
                                    .iter()
                                    .take(MAX_SUBROWS)
                                    .map(|item| {
                                        headers
                                            .iter()
                                            .map(|h| {
                                                item.get(h.as_str())
                                                    .map(compact)
                                                    .unwrap_or_default()
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                headers,
                                notes: Vec::new(),
                                total: items.len(),
                            });
                        }
                        Value::Array(items) => detail.push(Detail::Code(
                            label,
                            items
                                .iter()
                                .take(MAX_SUBROWS)
                                .map(compact)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        )),
                        Value::Object(_) => detail.push(Detail::Code(label, compact(value))),
                        other => detail.push(Detail::Prop(label, compact(other))),
                    }
                }
            }
            Row {
                title: None,
                subtitle: None,
                search: String::new(),
                name,
                cols: [first, String::new(), String::new()],
                tone: Tone::Neutral,
                detail,
            }
        })
        .collect();
    Table {
        title,
        description,
        headers: ["", "", ""],
        widths: [100., 0., 0.],
        empty,
        rows,
    }
}

fn claims_table(claims: &[Claim]) -> Table {
    let rows = claims
        .iter()
        .map(|c| {
            let subject = c.subject.as_ref();
            let kind = subject
                .and_then(|s| s.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let owner = subject
                .and_then(|s| s.get("owner").or_else(|| s.get("name")))
                .and_then(Value::as_str)
                .map(str::to_string);
            let mut detail = props(vec![
                ("Status", text(&c.status)),
                ("Usability", text(&c.usability)),
                ("Claim", text(&c.id)),
                ("Proof", text(&c.proof_id)),
            ]);
            if let Some(Value::Object(map)) = subject {
                detail.push(Detail::Table {
                    title: "Subject".into(),
                    headers: vec!["field".into(), "value".into()],
                    rows: map
                        .iter()
                        .map(|(k, v)| vec![k.replace('_', " "), compact(v)])
                        .collect(),
                    notes: Vec::new(),
                    total: map.len(),
                });
            }
            Row {
                title: None,
                subtitle: None,
                search: String::new(),
                name: owner.unwrap_or_else(|| text(&c.id)),
                cols: [kind, text(&c.status), text(&c.usability)],
                tone: match c.usability.as_deref() {
                    Some("verified") => Tone::Good,
                    Some("candidate" | "evidence-only") => Tone::Weak,
                    _ => Tone::Neutral,
                },
                detail,
            }
        })
        .collect();
    Table {
        title: "Claims",
        description: "Every fact the IR asserts, its proof, and whether it is safe to build against.",
        headers: ["subject", "status", "usability"],
        widths: [130., 100., 90.],
        empty: "No claims: this IR carries no proof graph.",
        rows,
    }
}

fn conflicts_table(conflicts: &[Conflict]) -> Table {
    let rows = conflicts
        .iter()
        .map(|c| {
            let mut detail = props(vec![
                (
                    "State",
                    if c.resolved {
                        "resolved".into()
                    } else {
                        "open".into()
                    },
                ),
                ("Conflict", text(&c.id)),
            ]);
            if let Some(reason) = &c.reason {
                detail.push(Detail::Code("Reason".into(), reason.clone()));
            }
            if !c.claim_ids.is_empty() {
                detail.push(Detail::Table {
                    title: "Claims involved".into(),
                    headers: vec!["claim".into()],
                    rows: c.claim_ids.iter().map(|id| vec![id.clone()]).collect(),
                    notes: Vec::new(),
                    total: c.claim_ids.len(),
                });
            }
            Row {
                title: None,
                subtitle: None,
                search: String::new(),
                name: text(&c.reason),
                cols: [
                    if c.resolved {
                        "resolved".into()
                    } else {
                        "open".into()
                    },
                    c.claim_ids.len().to_string(),
                    String::new(),
                ],
                tone: if c.resolved { Tone::Neutral } else { Tone::Bad },
                detail,
            }
        })
        .collect();
    Table {
        title: "Conflicts",
        description: "Where evidence disagrees. Windissect withholds the fact rather than pick a side.",
        headers: ["state", "claims", ""],
        widths: [70., 60., 0.],
        empty: "No conflicts: every claim agrees.",
        rows,
    }
}

pub fn load(path: &Path) -> anyhow::Result<Summary> {
    let file = File::open(path)?;
    let ir: IrFile = serde_json::from_reader(BufReader::with_capacity(1 << 20, file))?;
    let names: HashMap<&str, &str> = ir
        .symbols
        .iter()
        .filter_map(|s| {
            Some((
                s.id.as_deref()?,
                s.demangled.as_deref().or(s.mangled.as_deref())?,
            ))
        })
        .collect();
    let tables = vec![
        symbols_table(&ir.symbols),
        functions_table(&ir.functions, &names),
        types_table(&ir.types, &names),
        vtables_table(&ir.vtables, &names),
        generic_table(
            "Classes",
            "Classes with reflected properties (getters and setters the binary registers by name).",
            "No classes were recovered.",
            &ir.classes,
        ),
        generic_table(
            "Enums",
            "Enumerations with their named values.",
            "No enums were recovered.",
            &ir.enums,
        ),
        claims_table(&ir.claims),
        conflicts_table(&ir.conflicts),
    ];
    drop(names);
    Ok(Summary {
        binary: ir.binary,
        tables,
    })
}
