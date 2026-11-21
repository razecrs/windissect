//! Prove "instance method F hands `&this->member` to callee G, and G calls
//! vtable slot S on the object stored in that member".
//!
//! That is exactly how C++/WinRT code reads a projected property off a
//! member: `m_window.XamlContent()` compiles to `consume_...(&this->m_window,
//! &out)`, whose body loads the interface pointer from its argument and calls
//! one vtable slot. A consumer that needs the same value (the member's object
//! and the slot that yields what F used) can then use the proven offset and
//! slot instead of a typed-in one.
//!
//! Both halves are forward dataflow over the canonical instruction IR of the
//! exact build, across its control-flow graph:
//!   - in F, the abstract value of RCX starting from `this + 0` at entry; the
//!     proof is the call whose RCX is `this + k` (k > 0) on every path, and
//!     every such call in F must agree on k and callee;
//!   - in G, RCX at entry is the member's address P; `[P]` is the object O,
//!     `[O]` its vtable V, `[V + 8*s]` slot s; the proof is an indirect call
//!     through slot s with RCX = O (a method call on the member's object),
//!     either `call [V+imm]` or Control Flow Guard's `_guard_dispatch_icall`
//!     with RAX = slot s.
//!
//! Anything the analysis cannot follow (an unknown write to a tracked
//! register, a join of different values) becomes unknown, so the proof fails
//! rather than guesses.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::model::{Database, FunctionAnalysis, InstructionRecord};

/// What one proof established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCallProof {
    pub function: String,
    pub member_offset: u64,
    pub call_rva: u32,
    pub callee_rva: u32,
    pub slot: u64,
    pub slot_call_rva: u32,
}

/// Register names that alias RCX / RAX at any width.
fn reg_family(reg: &str) -> Option<&'static str> {
    match reg {
        "rcx" | "ecx" | "cx" | "cl" | "ch" => Some("rcx"),
        "rax" | "eax" | "ax" | "al" | "ah" => Some("rax"),
        "rdx" | "edx" | "dx" | "dl" | "dh" => Some("rdx"),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => Some("rbx"),
        "rsi" | "esi" | "si" | "sil" => Some("rsi"),
        "rdi" | "edi" | "di" | "dil" => Some("rdi"),
        "r8" | "r8d" | "r8w" | "r8b" => Some("r8"),
        "r9" | "r9d" | "r9w" | "r9b" => Some("r9"),
        "r10" | "r10d" | "r10w" | "r10b" => Some("r10"),
        "r11" | "r11d" | "r11w" | "r11b" => Some("r11"),
        _ => None,
    }
}

/// `38h`, `0x38`, `56` -> 56.
fn parse_imm(text: &str) -> Option<i64> {
    let t = text.trim();
    let (neg, t) = t.strip_prefix('-').map_or((false, t), |rest| (true, rest));
    let value = if let Some(hex) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = t.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        t.parse::<i64>().ok()?
    };
    Some(if neg { -value } else { value })
}

/// Operands of an instruction's text, split on the top-level comma.
fn operands(ins: &InstructionRecord) -> Vec<String> {
    let rest = ins.text.split_once(' ').map_or("", |(_, rest)| rest).trim();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in rest.chars() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// `[rcx]`, `qword ptr [rax+40h]` -> ("rcx", 0) / ("rax", 0x40). Only a single
/// base register plus an optional constant displacement.
fn memory_base_disp(operand: &str) -> Option<(&'static str, i64)> {
    let inner = operand.split_once('[')?.1.strip_suffix(']')?.trim();
    let (base, disp) = if let Some((b, d)) = inner.split_once('+') {
        (b.trim(), parse_imm(d)?)
    } else if let Some((b, d)) = inner.split_once('-') {
        (b.trim(), -parse_imm(d)?)
    } else {
        (inner, 0)
    };
    Some((reg_family(base)?, disp))
}

/// Mnemonics that read their first operand without writing it.
fn reads_only(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "cmp" | "test" | "push" | "bt" | "jmp" | "call" | "ret" | "nop" | "int3"
    ) || mnemonic.starts_with('j')
}

/// Successor RVAs of `ins` inside a function.
fn successors(ins: &InstructionRecord, next: Option<u32>) -> Vec<u32> {
    match ins.flow.as_str() {
        "return" | "interrupt" => Vec::new(),
        "unconditionalbranch" => ins.branch_target_rva.into_iter().collect(),
        "conditionalbranch" => ins.branch_target_rva.into_iter().chain(next).collect(),
        _ => next.into_iter().collect(),
    }
}

/// Forward dataflow over one function with a per-register abstract value `V`.
/// `transfer` updates the state for one instruction; `visit` sees the state
/// before each instruction once the fixpoint is reached.
fn dataflow<V: Clone + PartialEq>(
    f: &FunctionAnalysis,
    entry: BTreeMap<&'static str, V>,
    transfer: impl Fn(&InstructionRecord, &mut BTreeMap<&'static str, V>),
    mut visit: impl FnMut(&InstructionRecord, &BTreeMap<&'static str, V>),
) {
    let index: HashMap<u32, usize> = f
        .instructions
        .iter()
        .enumerate()
        .map(|(i, ins)| (ins.rva, i))
        .collect();
    let mut states: Vec<Option<BTreeMap<&'static str, V>>> = vec![None; f.instructions.len()];
    let mut queue = VecDeque::new();
    if f.instructions.is_empty() {
        return;
    }
    states[0] = Some(entry);
    queue.push_back(0usize);
    let mut rounds = 0usize;
    while let Some(i) = queue.pop_front() {
        rounds += 1;
        if rounds > f.instructions.len() * 64 {
            break; // cannot happen with a finite lattice; a hard stop all the same
        }
        let Some(mut state) = states[i].clone() else {
            continue;
        };
        let ins = &f.instructions[i];
        transfer(ins, &mut state);
        let next = f.instructions.get(i + 1).map(|n| n.rva);
        for succ in successors(ins, next) {
            let Some(&j) = index.get(&succ) else { continue };
            let merged = states[j].as_ref().map_or_else(
                || state.clone(),
                |old| {
                    let mut m = old.clone();
                    // Keep only agreeing registers: a disagreement is unknown.
                    m.retain(|reg, value| state.get(reg) == Some(value));
                    m
                },
            );
            if states[j].as_ref() != Some(&merged) {
                states[j] = Some(merged);
                queue.push_back(j);
            }
        }
    }
    for (i, ins) in f.instructions.iter().enumerate() {
        if let Some(state) = &states[i] {
            visit(ins, state);
        }
    }
}

/// Abstract register value in G.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ptr {
    Arg,       // the member's address
    Obj,       // [Arg]: the member's object
    Vtbl,      // [Obj]
    Slot(u64), // [Vtbl + 8*s]
}

fn clobber_volatiles<V>(state: &mut BTreeMap<&'static str, V>) {
    for reg in ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"] {
        state.remove(reg);
    }
}

/// Generic write handling: the destination register (first operand) loses
/// its tracked value unless the specific transfer set it.
fn written_register(ins: &InstructionRecord) -> Option<&'static str> {
    if reads_only(&ins.mnemonic) {
        return None;
    }
    let ops = operands(ins);
    reg_family(ops.first()?.as_str())
}

fn transfer_this(ins: &InstructionRecord, state: &mut BTreeMap<&'static str, i64>) {
    let ops = operands(ins);
    let m = ins.mnemonic.as_str();
    if ins.flow == "call" {
        clobber_volatiles(state);
        return;
    }
    if m.starts_with("rep") || matches!(m, "xchg" | "cmpxchg" | "loop" | "cpuid" | "syscall") {
        state.remove("rcx");
        state.remove("rax");
        return;
    }
    if ops.first().map(String::as_str) == Some("rcx") {
        let current = state.get("rcx").copied();
        let new = match (m, ops.get(1), current) {
            ("add", Some(imm), Some(k)) => parse_imm(imm).map(|v| k + v),
            ("sub", Some(imm), Some(k)) => parse_imm(imm).map(|v| k - v),
            ("lea", Some(mem), _) => memory_base_disp(mem)
                .filter(|(base, _)| *base == "rcx")
                .and_then(|(_, d)| current.map(|k| k + d)),
            _ => None,
        };
        match new {
            Some(v) => {
                state.insert("rcx", v);
            }
            None => {
                state.remove("rcx");
            }
        }
        return;
    }
    if let Some(reg) = written_register(ins) {
        state.remove(reg);
    }
}

fn transfer_member(ins: &InstructionRecord, state: &mut BTreeMap<&'static str, Ptr>) {
    let ops = operands(ins);
    let m = ins.mnemonic.as_str();
    if ins.flow == "call" {
        clobber_volatiles(state);
        return;
    }
    if m.starts_with("rep") || matches!(m, "xchg" | "cmpxchg" | "loop" | "cpuid" | "syscall") {
        state.remove("rcx");
        state.remove("rax");
        return;
    }
    let Some(dest) = ops.first().and_then(|d| reg_family(d)) else {
        return; // memory destination: registers unchanged
    };
    if reads_only(m) {
        return;
    }
    let value = match (m, ops.get(1)) {
        ("mov", Some(src)) if src.contains('[') => {
            memory_base_disp(src).and_then(|(base, disp)| match (state.get(base), disp) {
                (Some(Ptr::Arg), 0) => Some(Ptr::Obj),
                (Some(Ptr::Obj), 0) => Some(Ptr::Vtbl),
                (Some(Ptr::Vtbl), d) if d >= 0 && d % 8 == 0 => {
                    Some(Ptr::Slot(u64::try_from(d / 8).ok()?))
                }
                _ => None,
            })
        }
        ("mov", Some(src)) => reg_family(src).and_then(|r| state.get(r).cloned()),
        _ => None,
    };
    match value {
        Some(v) => {
            state.insert(dest, v);
        }
        None => {
            state.remove(dest);
        }
    }
}

fn is_instance_method(mangled: &str) -> bool {
    // MSVC: @@ then access/class (Q,A,I,U,E,M,...) then E (x64 this) then cv.
    // Static members use S/K/C (no this) and free functions use Y/Z.
    mangled
        .split_once("@@")
        .and_then(|(_, rest)| rest.chars().next())
        .is_some_and(|c| matches!(c, 'Q' | 'A' | 'I' | 'B' | 'U' | 'E' | 'M' | 'R' | 'V' | 'F'))
}

fn find_function<'a>(db: &'a Database, symbol: &str) -> Result<&'a FunctionAnalysis> {
    let mut found = db
        .functions
        .iter()
        .filter(|f| f.symbol_ids.iter().any(|s| s == symbol));
    let Some(f) = found.next() else {
        bail!("{symbol} has no analysed function in this IR");
    };
    if found.next().is_some() {
        bail!("{symbol} names more than one analysed function");
    }
    Ok(f)
}

fn function_at(db: &Database, rva: u32) -> Option<&FunctionAnalysis> {
    db.functions.iter().find(|f| f.rva == rva)
}

/// RVAs of Control Flow Guard's indirect-call dispatcher thunks.
fn guard_dispatch_rvas(db: &Database) -> BTreeSet<u32> {
    let Some(base) = db.binary.image_base else {
        return BTreeSet::new();
    };
    db.symbols
        .iter()
        .filter(|s| s.mangled.contains("guard_dispatch_icall"))
        .filter_map(|s| u32::try_from(s.vaddr.checked_sub(base)?).ok())
        .collect()
}

/// Prove the member-call chain rooted at the instance method `symbol`.
fn prove_with(
    db: &Database,
    symbol: &str,
    guard_targets: &BTreeSet<u32>,
) -> Result<MemberCallProof> {
    if !is_instance_method(symbol) {
        bail!("{symbol} is not an instance method: RCX is not `this`");
    }
    let f = find_function(db, symbol)?;

    // F: calls whose RCX is this + k (k > 0) on every path into them.
    let mut member_calls: BTreeSet<(i64, u32, u32)> = BTreeSet::new();
    dataflow(
        f,
        BTreeMap::from([("rcx", 0i64)]),
        transfer_this,
        |ins, state| {
            if ins.flow == "call"
                && let (Some(&k), Some(target)) = (state.get("rcx"), ins.branch_target_rva)
                && k > 0
            {
                member_calls.insert((k, target, ins.rva));
            }
        },
    );
    let distinct: BTreeSet<(i64, u32)> = member_calls.iter().map(|(k, t, _)| (*k, *t)).collect();
    let Some(&(offset, callee_rva)) = distinct.iter().next() else {
        bail!("{symbol} passes no `this`-member address to a direct call");
    };
    if distinct.len() > 1 {
        bail!(
            "{symbol} passes several member addresses or callees: {distinct:?}; not a single accessor"
        );
    }
    let call_rva = member_calls.iter().next().map_or(0, |(_, _, rva)| *rva);

    // G: an indirect call through [[[arg]] + 8*s] with RCX = [arg].
    let Some(g) = function_at(db, callee_rva) else {
        bail!("callee at RVA 0x{callee_rva:X} has no analysed function");
    };
    let mut slot_calls: BTreeSet<(u64, u32)> = BTreeSet::new();
    dataflow(
        g,
        BTreeMap::from([("rcx", Ptr::Arg)]),
        transfer_member,
        |ins, state| {
            if ins.flow != "call" || state.get("rcx") != Some(&Ptr::Obj) {
                return;
            }
            let ops = operands(ins);
            let direct = ops
                .first()
                .and_then(|op| memory_base_disp(op))
                .and_then(|(base, d)| {
                    (state.get(base) == Some(&Ptr::Vtbl) && d >= 0 && d % 8 == 0)
                        .then(|| u64::try_from(d / 8).ok())
                        .flatten()
                });
            let guarded = ins
                .branch_target_rva
                .filter(|t| guard_targets.contains(t))
                .and_then(|_| match state.get("rax") {
                    Some(Ptr::Slot(s)) => Some(*s),
                    _ => None,
                });
            if let Some(slot) = direct.or(guarded) {
                slot_calls.insert((slot, ins.rva));
            }
        },
    );
    let slots: BTreeSet<u64> = slot_calls.iter().map(|(s, _)| *s).collect();
    let Some(&slot) = slots.iter().next() else {
        bail!("callee 0x{callee_rva:X} makes no vtable call on the member's object");
    };
    if slots.len() > 1 {
        bail!("callee 0x{callee_rva:X} calls several slots {slots:?} on the member's object");
    }
    Ok(MemberCallProof {
        function: symbol.to_string(),
        member_offset: u64::try_from(offset).context("negative member offset")?,
        call_rva,
        callee_rva,
        slot,
        slot_call_rva: slot_calls.iter().next().map_or(0, |(_, rva)| *rva),
    })
}

fn c_ident(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// `--want NAME=SYMBOL`: prove each and write `<stem>_proofs.h` (+ .json).
/// Nothing is written unless every wanted proof holds.
pub fn emit(db: &Database, wants: &[String], stem: &str, out_dir: &Path) -> Result<()> {
    emit_with(db, wants, stem, out_dir, &guard_dispatch_rvas(db))
}

fn emit_with(
    db: &Database,
    wants: &[String],
    stem: &str,
    out_dir: &Path,
    guard_targets: &BTreeSet<u32>,
) -> Result<()> {
    if wants.is_empty() {
        bail!("prove-member-call needs at least one --want NAME=SYMBOL");
    }
    let mut proofs = Vec::new();
    for want in wants {
        let Some((name, symbol)) = want.split_once('=') else {
            bail!("--want expects NAME=SYMBOL, got {want}");
        };
        let proof =
            prove_with(db, symbol, guard_targets).with_context(|| format!("proving {name}"))?;
        proofs.push((c_ident(name).to_ascii_uppercase(), proof));
    }
    let upper = c_ident(stem).to_ascii_uppercase();
    let timestamp = db
        .binary
        .timestamp
        .as_deref()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let guid = db.binary.pdb_guid.as_deref().unwrap_or("unknown");
    let mut h = String::new();
    let _ = writeln!(
        h,
        "/* Generated by windissect prove-member-call. Do not edit.\n   Proven from the canonical instruction IR of {} (PDB {} age {}).\n   Valid only for that exact build: compare _PE_TIMESTAMP with the module's\n   symbol table before use. */\n#ifndef {upper}_PROOFS_H\n#define {upper}_PROOFS_H\n\n#define {upper}_PROOFS_PE_TIMESTAMP {timestamp}U\n",
        db.binary.file,
        guid,
        db.binary.pdb_age.unwrap_or(0)
    );
    let mut json_rows = Vec::new();
    for (name, p) in &proofs {
        let _ = writeln!(
            h,
            "/* {name}: {} passes &this->+0x{:X} to the call at RVA 0x{:X} (callee 0x{:X}),\n   which calls vtable slot {} of the object stored there at RVA 0x{:X}. */\n#define {upper}_{name}_MEMBER_OFFSET 0x{:X}u\n#define {upper}_{name}_SLOT {}u\n",
            p.function,
            p.member_offset,
            p.call_rva,
            p.callee_rva,
            p.slot,
            p.slot_call_rva,
            p.member_offset,
            p.slot
        );
        json_rows.push(json!({
            "name": name, "function": p.function, "member_offset": p.member_offset,
            "call_rva": p.call_rva, "callee_rva": p.callee_rva, "slot": p.slot,
            "slot_call_rva": p.slot_call_rva,
        }));
    }
    let _ = writeln!(h, "#endif");
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let ident = c_ident(stem);
    crate::diff::atomic_write(&out_dir.join(format!("{ident}_proofs.h")), h.as_bytes())?;
    crate::diff::atomic_write(
        &out_dir.join(format!("{ident}_proofs.json")),
        serde_json::to_vec_pretty(
            &json!({"binary": db.binary.file, "pdb_guid": guid, "proofs": json_rows}),
        )?
        .as_slice(),
    )?;
    println!(
        "proved {} member call(s) -> {}/{ident}_proofs.h",
        proofs.len(),
        out_dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(rva: u32, text: &str, flow: &str, target: Option<u32>) -> InstructionRecord {
        InstructionRecord {
            rva,
            length: 1,
            bytes: String::new(),
            mnemonic: text.split(' ').next().unwrap().to_string(),
            text: text.to_string(),
            flow: flow.to_string(),
            branch_target_rva: target,
            memory_target_rva: None,
            data_reference: None,
        }
    }

    fn func(rva: u32, symbol: &str, instructions: Vec<InstructionRecord>) -> FunctionAnalysis {
        FunctionAnalysis {
            rva,
            size: 64,
            symbol_ids: vec![symbol.to_string()],
            instructions,
            cfg_edges: Vec::new(),
        }
    }

    const SET_THEME: &str = "?SetTheme@Host@@QEAAXH@Z";

    /// The shape of `TaskbarHost::SetTheme` -> `consume_...::XamlContent`.
    fn sample(extra_write: bool) -> Database {
        let mut db = Database::default();
        db.binary.image_base = Some(0x1_8000_0000);
        let mut f = vec![
            ins(0x100, "mov [rcx+150h],edx", "next", None),
            ins(0x101, "sub edx,1", "next", None),
            ins(
                0x102,
                "jne short 0000000180000110h",
                "conditionalbranch",
                Some(0x110),
            ),
            ins(0x103, "lea rdi,[rcx+50h]", "next", None),
            ins(0x104, "add rcx,38h", "next", None),
        ];
        if extra_write {
            f.push(ins(0x105, "mov rcx,[rbx]", "next", None));
        }
        f.extend([
            ins(0x106, "call 0000000180000200h", "call", Some(0x200)),
            ins(0x107, "ret", "return", None),
            ins(
                0x110,
                "jmp short 0000000180000103h",
                "unconditionalbranch",
                Some(0x103),
            ),
        ]);
        db.functions.push(func(0x100, SET_THEME, f));
        db.functions.push(func(
            0x200,
            "?XamlContent@consume@@QEBA@XZ",
            vec![
                ins(0x200, "mov rbx,rdx", "next", None),
                ins(0x201, "mov rcx,[rcx]", "next", None),
                ins(0x202, "lea rdx,[rsp+40h]", "next", None),
                ins(0x203, "mov rax,[rcx]", "next", None),
                ins(0x204, "mov rax,[rax+40h]", "next", None),
                ins(0x205, "call 0000000180000300h", "call", Some(0x300)),
                ins(0x206, "ret", "return", None),
            ],
        ));
        db
    }

    fn guard() -> BTreeSet<u32> {
        BTreeSet::from([0x300])
    }

    #[test]
    fn proves_member_offset_and_slot_across_branches() {
        let p = prove_with(&sample(false), SET_THEME, &guard()).unwrap();
        assert_eq!(p.member_offset, 0x38);
        assert_eq!(p.callee_rva, 0x200);
        assert_eq!(p.slot, 8);
        assert_eq!(p.slot_call_rva, 0x205);
    }

    #[test]
    fn refuses_when_rcx_is_overwritten_or_not_this() {
        assert!(prove_with(&sample(true), SET_THEME, &guard()).is_err());
        assert!(prove_with(&sample(false), "?Free@@YAXXZ", &guard()).is_err());
        // Without the guard thunk known, the indirect call is not proven.
        assert!(prove_with(&sample(false), SET_THEME, &BTreeSet::new()).is_err());
    }

    #[test]
    fn writes_header_only_when_every_proof_holds() {
        let dir = std::env::temp_dir().join(format!("windissect-pmc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = sample(false);
        emit_with(
            &db,
            &[format!("HostXaml={SET_THEME}")],
            "tb",
            &dir,
            &guard(),
        )
        .unwrap();
        let h = std::fs::read_to_string(dir.join("tb_proofs.h")).unwrap();
        assert!(h.contains("#define TB_HOSTXAML_MEMBER_OFFSET 0x38u"));
        assert!(h.contains("#define TB_HOSTXAML_SLOT 8u"));
        let dir2 = dir.join("bad");
        assert!(
            emit_with(
                &sample(true),
                &[format!("HostXaml={SET_THEME}")],
                "tb",
                &dir2,
                &guard()
            )
            .is_err()
        );
        assert!(!dir2.join("tb_proofs.h").exists());
    }

    #[test]
    fn proves_a_direct_vtable_call_too() {
        let mut db = sample(false);
        let g = db.functions.iter_mut().find(|f| f.rva == 0x200).unwrap();
        g.instructions[4] = ins(0x204, "nop", "next", None);
        g.instructions[5] = ins(0x205, "call qword ptr [rax+30h]", "call", None);
        let p = prove_with(&db, SET_THEME, &BTreeSet::new()).unwrap();
        assert_eq!(p.slot, 6);
    }

    #[test]
    fn parses_operands_and_memory() {
        assert_eq!(parse_imm("38h"), Some(0x38));
        assert_eq!(memory_base_disp("qword ptr [rax+40h]"), Some(("rax", 0x40)));
        assert_eq!(memory_base_disp("[rcx]"), Some(("rcx", 0)));
        let i = ins(0, "mov [rsp+20h],rax", "next", None);
        assert_eq!(
            operands(&i),
            vec!["[rsp+20h]".to_string(), "rax".to_string()]
        );
    }
}
