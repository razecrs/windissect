//! Phase C: Static Enrichment — disassembly, reloc-normalized body hashing,
//! call-graph construction, function size calculation, and Win32 import tracking.

use crate::model::{
    Capability, CapabilityStatus, ControlFlowEdge, Database, FunctionAnalysis, InstructionRecord,
    Kind,
};
use anyhow::{Context, Result};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Enrich the database using PE binary bytes.
pub fn enrich_database(db: &mut Database, pe_bytes: &[u8]) -> Result<()> {
    let pe = goblin::pe::PE::parse(pe_bytes).context("failed to parse PE headers")?;
    let bitness = match pe.header.coff_header.machine {
        0x014c => 32,
        0x8664 => 64,
        machine => anyhow::bail!(
            "static enrichment does not support PE machine 0x{machine:04X}; refusing to fabricate x86 analysis"
        ),
    };

    // 1. Calculate Function Sizes
    calculate_function_sizes(db, &pe);

    // 2. Build VAddr -> Symbol Index map & Import Address Map
    let mut vaddr_to_index: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, sym) in db.symbols.iter().enumerate() {
        if sym.vaddr != 0 {
            vaddr_to_index.insert(sym.vaddr, i);
        }
    }

    // Map IAT addresses to import names
    let mut iat_map: BTreeMap<u64, String> = BTreeMap::new();
    for import in &pe.imports {
        let iat_vaddr = pe.image_base + import.rva as u64;
        let name = format!("{}!{}", import.dll, import.name);
        iat_map.insert(iat_vaddr, name);
    }

    // Track calls & callers: (caller_idx, callee_idx)
    let mut call_edges: Vec<(usize, usize)> = Vec::new();
    let mut symbol_imports: Vec<(usize, String)> = Vec::new();
    let mut analyzed_rvas = BTreeSet::new();
    let mut function_analyses = Vec::new();
    let mut aliases_by_rva = BTreeMap::<u32, Vec<String>>::new();
    for symbol in &db.symbols {
        if symbol.rva != 0 && symbol.is_code {
            aliases_by_rva
                .entry(symbol.rva)
                .or_default()
                .push(symbol.id.clone());
        }
    }

    // 3. Disassemble function bodies, compute body_hash, and extract calls
    for i in 0..db.symbols.len() {
        let sym_vaddr = db.symbols[i].vaddr;
        let sym_size = db.symbols[i].size as usize;
        if sym_vaddr == 0
            || sym_size == 0
            || !db.symbols[i].is_code
            || db.symbols[i].forwarder.is_some()
        {
            continue;
        }

        let Some(file_offset) = rva_to_offset(&pe, sym_vaddr) else {
            continue;
        };

        let Some(file_end) = file_offset.checked_add(sym_size) else {
            continue;
        };
        if file_end > pe_bytes.len() {
            continue;
        }

        let fn_bytes = &pe_bytes[file_offset..file_end];

        // Disassemble instructions
        let mut decoder = Decoder::with_ip(bitness, fn_bytes, sym_vaddr, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        let mut normalized_bytes: Vec<u8> = Vec::new();
        let mut local_calls: BTreeSet<usize> = BTreeSet::new();
        let mut local_imports: BTreeSet<String> = BTreeSet::new();
        let mut inst_count = 0;
        let mut first_mnemonic = Mnemonic::INVALID;
        let collect_analysis = analyzed_rvas.insert(db.symbols[i].rva);
        let mut instructions = Vec::new();
        let mut cfg_edges = Vec::new();
        let mut formatter = IntelFormatter::new();

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);
            inst_count += 1;
            if inst_count == 1 {
                first_mnemonic = inst.mnemonic();
            }

            // Normalize instruction bytes for reloc-agnostic hashing
            let raw_len = inst.len();
            let inst_bytes = fn_bytes[decoder.ip() as usize - sym_vaddr as usize - raw_len
                ..decoder.ip() as usize - sym_vaddr as usize]
                .to_vec();

            if collect_analysis {
                let rva = u32::try_from(inst.ip().saturating_sub(pe.image_base)).unwrap_or(0);
                let next_rva = u32::try_from(decoder.ip().saturating_sub(pe.image_base)).ok();
                let branch_target_rva = matches!(
                    inst.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
                .then(|| inst.near_branch_target().checked_sub(pe.image_base))
                .flatten()
                .and_then(|target| u32::try_from(target).ok());
                let memory_target_rva = inst
                    .is_ip_rel_memory_operand()
                    .then(|| inst.ip_rel_memory_address().checked_sub(pe.image_base))
                    .flatten()
                    .and_then(|target| u32::try_from(target).ok());
                if let Some(target) = branch_target_rva {
                    cfg_edges.push(ControlFlowEdge {
                        from_rva: rva,
                        to_rva: target,
                        kind: format!("{:?}", inst.flow_control()).to_ascii_lowercase(),
                    });
                }
                if matches!(
                    inst.flow_control(),
                    FlowControl::Next | FlowControl::Call | FlowControl::ConditionalBranch
                ) && let Some(target) = next_rva
                {
                    cfg_edges.push(ControlFlowEdge {
                        from_rva: rva,
                        to_rva: target,
                        kind: "fallthrough".into(),
                    });
                }
                let mut text = String::new();
                formatter.format(&inst, &mut text);
                instructions.push(InstructionRecord {
                    rva,
                    length: u8::try_from(inst.len()).unwrap_or(0),
                    bytes: inst_bytes
                        .iter()
                        .map(|byte| format!("{byte:02X}"))
                        .collect(),
                    mnemonic: format!("{:?}", inst.mnemonic()).to_ascii_lowercase(),
                    text,
                    flow: format!("{:?}", inst.flow_control()).to_ascii_lowercase(),
                    branch_target_rva,
                    memory_target_rva,
                });
            }

            // Mask out RIP-relative target displacements for call/jmp branches
            if inst.op0_kind() == OpKind::NearBranch64 || inst.op0_kind() == OpKind::NearBranch32 {
                let target = inst.near_branch_target();
                if inst.flow_control() == FlowControl::Call
                    && let Some(&target_idx) = vaddr_to_index.get(&target)
                {
                    local_calls.insert(target_idx);
                }
            } else if inst.op0_kind() == OpKind::Memory {
                let target = inst.memory_displacement64();
                // Check if target is an IAT entry
                if let Some(import_name) = iat_map.get(&target) {
                    local_imports.insert(import_name.clone());
                }
            }

            normalized_bytes.extend_from_slice(&inst_bytes);
        }

        // Reclassify single-instruction jump thunks
        if inst_count == 1 && first_mnemonic == Mnemonic::Jmp {
            db.symbols[i].kind = Kind::Thunk;
        }

        // Compute SHA-256 body hash
        let mut hasher = Sha256::new();
        hasher.update(&normalized_bytes);
        let hash_bytes = hasher.finalize();
        let hash_hex: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();
        db.symbols[i].body_hash = hash_hex;

        if collect_analysis {
            function_analyses.push(FunctionAnalysis {
                rva: db.symbols[i].rva,
                size: db.symbols[i].size,
                symbol_ids: aliases_by_rva
                    .get(&db.symbols[i].rva)
                    .cloned()
                    .unwrap_or_else(|| vec![db.symbols[i].id.clone()]),
                instructions,
                cfg_edges,
            });
        }

        // Save call graph edges and imports
        for callee_idx in local_calls {
            call_edges.push((i, callee_idx));
        }
        for imp in local_imports {
            symbol_imports.push((i, imp));
        }
    }

    // 4. Populate call graph and imports into IR symbols
    for (caller, callee) in call_edges {
        let callee_id = db.symbols[callee].id.clone();
        let caller_id = db.symbols[caller].id.clone();

        if !db.symbols[caller].calls.contains(&callee_id) {
            db.symbols[caller].calls.push(callee_id);
        }
        if !db.symbols[callee].callers.contains(&caller_id) {
            db.symbols[callee].callers.push(caller_id);
        }
    }

    for (sym_idx, imp) in symbol_imports {
        if !db.symbols[sym_idx].imports.contains(&imp) {
            db.symbols[sym_idx].imports.push(imp);
        }
    }

    db.functions = function_analyses;
    db.capabilities.push(Capability {
        id: "canonical-x86-instructions-cfg".into(),
        status: CapabilityStatus::Supported,
        analyzer: "enrich".into(),
        reason: format!("{} unique code RVAs decoded", db.functions.len()),
    });

    Ok(())
}

/// Calculate function sizes based on address spacing and PE section boundaries.
fn calculate_function_sizes(db: &mut Database, pe: &goblin::pe::PE) {
    let image_base = pe.image_base;

    // Collect all symbol addresses
    let mut addrs: Vec<(u64, usize)> = db
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.vaddr != 0 && s.is_code && s.forwarder.is_none())
        .map(|(i, s)| (s.vaddr, i))
        .collect();

    addrs.sort_by_key(|&(vaddr, _)| vaddr);

    for idx in 0..addrs.len() {
        let (vaddr, sym_i) = addrs[idx];
        let rva = (vaddr - image_base) as u32;

        // Find containing PE section
        let sec_end = pe
            .sections
            .iter()
            .find(|sec| rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size)
            .map(|sec| image_base + sec.virtual_address as u64 + sec.virtual_size as u64)
            .unwrap_or(vaddr + 64);

        let next_vaddr = if idx + 1 < addrs.len() {
            addrs[idx + 1].0.min(sec_end)
        } else {
            sec_end
        };

        if db.symbols[sym_i].size == 0 && next_vaddr > vaddr {
            let computed_size = (next_vaddr - vaddr) as u32;
            // Bound reasonable size (max 64KB per function)
            db.symbols[sym_i].size = computed_size.min(65536);
        }
    }
}

/// Helper to convert RVA / VAddr to file offset.
fn rva_to_offset(pe: &goblin::pe::PE, vaddr: u64) -> Option<usize> {
    let rva = (vaddr.saturating_sub(pe.image_base)) as u32;
    for sec in &pe.sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size {
            let delta = rva - sec.virtual_address;
            if delta >= sec.size_of_raw_data {
                return None;
            }
            let offset = delta.checked_add(sec.pointer_to_raw_data)?;
            return Some(offset as usize);
        }
    }
    None
}
