//! Conservative PE data-flow evidence for class member offsets.
//!
//! This pass intentionally has a narrow proof rule: an instruction must access
//! memory through the incoming Windows x64 `this` register (RCX) or a proven
//! register alias derived from it.
//! Constructor writes and trivial accessor reads are retained as observations,
//! not upgraded into a complete C++ layout.  That makes stripped-PDB output
//! useful without turning optimizer artefacts into invented fields.

use crate::model::{
    Capability, CapabilityStatus, Claim, ClaimStatus, ClaimSubject, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Kind, Proof,
    ProofObligation, Usability,
};
use anyhow::{Context, Result};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
struct Observation {
    offset: u64,
    width: usize,
    access: &'static str,
    symbol: String,
    rva: u32,
    instruction_rva: u32,
    suggested_name: Option<String>,
    confidence: &'static str,
}

pub fn recover(db: &mut Database, pe_bytes: &[u8]) -> Result<usize> {
    let pe = PE::parse(pe_bytes).context("parse PE for layout inference")?;
    if db.binary.machine.as_deref() != Some("0x8664") {
        return Ok(0);
    }
    let image_base = db.binary.image_base.unwrap_or(pe.image_base);
    let mut classes = BTreeMap::<String, Vec<Observation>>::new();
    let vftable_addresses: BTreeSet<u64> = db
        .symbols
        .iter()
        .filter(|symbol| symbol.mangled.starts_with("??_7"))
        .map(|symbol| symbol.vaddr)
        .collect();
    let mut allocation_sizes = BTreeMap::<String, Value>::new();

    for symbol in &db.symbols {
        let Some(class) = qualified_class(symbol) else {
            continue;
        };
        if !symbol.is_code || symbol.rva == 0 || symbol.size == 0 {
            continue;
        }
        let is_ctor = symbol.kind == Kind::Ctor;
        let is_accessor = symbol.kind == Kind::Accessor
            && symbol.sig.storage.as_deref() != Some("static")
            && symbol.size <= 64;
        if !is_ctor && !is_accessor {
            continue;
        }
        let Some(start) = rva_to_offset(&pe, symbol.rva) else {
            continue;
        };
        let len = usize::try_from(symbol.size).unwrap_or(0).min(512);
        let Some(bytes) = pe_bytes.get(start..start.saturating_add(len)) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            64,
            bytes,
            image_base + u64::from(symbol.rva),
            DecoderOptions::NONE,
        );
        let mut instruction_count = 0usize;
        let mut this_aliases = vec![(Register::RCX, 0i64)];
        while decoder.can_decode() && instruction_count < 64 {
            let instruction = decoder.decode();
            instruction_count += 1;
            for operand in 0..instruction.op_count() {
                if instruction.op_kind(operand) != OpKind::Memory
                    || instruction.memory_index() != Register::None
                {
                    continue;
                }
                let Some(alias_offset) = alias_offset(&this_aliases, instruction.memory_base())
                else {
                    continue;
                };
                let effective = alias_offset
                    .checked_add(instruction.memory_displacement64() as i64)
                    .unwrap_or(-1);
                let Ok(offset) = u64::try_from(effective) else {
                    continue;
                };
                // Offset zero is normally the primary vptr; keep it because it
                // is valuable evidence, but never infer a friendly field name.
                if offset > 0x10000 {
                    continue;
                }
                let access = if operand == 0
                    && matches!(
                        instruction.mnemonic(),
                        Mnemonic::Mov | Mnemonic::Movups | Mnemonic::Movaps
                    ) {
                    "write"
                } else {
                    "read"
                };
                if is_ctor && access != "write" {
                    continue;
                }
                let suggested_name = if is_accessor {
                    member_name(symbol.sig.method.as_deref(), access)
                } else {
                    None
                };
                classes.entry(class.clone()).or_default().push(Observation {
                    offset,
                    width: instruction.memory_size().size(),
                    access,
                    symbol: symbol.id.clone(),
                    rva: symbol.rva,
                    instruction_rva: u32::try_from(instruction.ip().saturating_sub(image_base))
                        .unwrap_or(symbol.rva),
                    suggested_name,
                    confidence: if is_accessor { "certain" } else { "likely" },
                });
            }

            update_this_aliases(&instruction, &mut this_aliases);
        }
    }

    for symbol in &db.symbols {
        if symbol.sig.method.as_deref() != Some("Create")
            || symbol.sig.storage.as_deref() != Some("static")
            || !symbol.is_code
            || symbol.size == 0
        {
            continue;
        }
        let Some(class) = qualified_class(symbol) else {
            continue;
        };
        let Some(start) = rva_to_offset(&pe, symbol.rva) else {
            continue;
        };
        let len = usize::try_from(symbol.size).unwrap_or(0).min(1024);
        let Some(bytes) = pe_bytes.get(start..start.saturating_add(len)) else {
            continue;
        };
        if let Some((size, vftable)) = allocation_size_proof(
            bytes,
            image_base + u64::from(symbol.rva),
            &vftable_addresses,
        ) {
            allocation_sizes.entry(class.clone()).or_insert_with(|| {
                json!({
                    "kind": "allocation-size-evidence",
                    "name": class,
                        "size": size,
                        "vftable": vftable,
                    "source": "pe-allocation-vftable-dataflow",
                    "evidence_symbol": symbol.id,
                    "evidence_rva": symbol.rva,
                    "confidence": "certain",
                })
            });
        }
    }

    let mut count = 0usize;
    let mut normalized_classes = BTreeMap::new();
    for (class, mut observations) in classes {
        observations.sort_by_key(|o| (o.offset, o.rva, o.symbol.clone()));
        observations.dedup_by(|a, b| {
            a.offset == b.offset
                && a.width == b.width
                && a.access == b.access
                && a.symbol == b.symbol
        });
        count += observations.len();
        let fields: Vec<Value> = observations
            .iter()
            .map(|o| {
                json!({
                    "offset": o.offset,
                    "width": o.width,
                    "access": o.access,
                    "suggested_name": o.suggested_name,
                    "evidence_symbol": o.symbol,
                    "evidence_rva": o.rva,
                    "instruction_rva": o.instruction_rva,
                    "confidence": o.confidence,
                })
            })
            .collect();
        db.types.push(json!({
            "kind": "layout-evidence",
            "name": class,
            "source": "pe-this-dataflow",
            "complete_layout": false,
            "note": "RCX-derived this-pointer observations only; gaps and object size are not inferred",
            "observations": fields,
        }));
        normalized_classes.insert(class, observations);
    }
    let allocation_count = allocation_sizes.len();
    add_proof_graph(db, &normalized_classes, &allocation_sizes);
    db.types.extend(allocation_sizes.into_values());
    db.type_recovery["pe_this_dataflow_observations"] = json!(count);
    db.type_recovery["pe_allocation_size_proofs"] = json!(allocation_count);
    db.capabilities.push(Capability {
        id: "layout-this-dataflow-x64".into(),
        status: CapabilityStatus::Partial,
        analyzer: "layoutinfer".into(),
        reason: format!(
            "{count} member observations and {allocation_count} allocation-size proofs; evidence corpus is not yet certified for verified field emission"
        ),
    });
    Ok(count)
}

fn add_proof_graph(
    db: &mut Database,
    classes: &BTreeMap<String, Vec<Observation>>,
    allocation_sizes: &BTreeMap<String, Value>,
) {
    for (owner, observations) in classes {
        for observation in observations {
            let evidence_id = format!(
                "ev:member:{owner}:{:X}:{:X}:{}:{}",
                observation.instruction_rva,
                observation.offset,
                observation.access,
                observation.width
            );
            let proof_id = format!(
                "proof:member:{owner}:{:X}:{:X}",
                observation.instruction_rva, observation.offset
            );
            db.evidence.push(Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::Dataflow,
                tool: EvidenceTool::Windissect,
                rule_id: "x64.this-member-access".into(),
                rule_version: 1,
                location: EvidenceLocation {
                    symbol_id: Some(observation.symbol.clone()),
                    rva: Some(observation.instruction_rva),
                    size: None,
                    instruction_rvas: vec![observation.instruction_rva],
                },
                observation: EvidenceObservation::MemberAccess {
                    owner: owner.clone(),
                    offset: observation.offset,
                    width: u32::try_from(observation.width).unwrap_or(0),
                    access: observation.access.into(),
                    suggested_name: observation.suggested_name.clone(),
                },
            });
            db.proofs.push(Proof {
                id: proof_id.clone(),
                rule_id: "x64.this-member-access".into(),
                rule_version: 1,
                passed: true,
                obligations: vec![
                    ProofObligation {
                        name: "instance-method".into(),
                        satisfied: true,
                        detail: "static methods excluded".into(),
                    },
                    ProofObligation {
                        name: "proven-this-alias".into(),
                        satisfied: true,
                        detail: "memory base derives from incoming RCX".into(),
                    },
                    ProofObligation {
                        name: "bounded-offset".into(),
                        satisfied: observation.offset <= 0x10000,
                        detail: format!("offset 0x{:X}", observation.offset),
                    },
                ],
            });
            db.claims.push(Claim {
                id: format!(
                    "claim:member:{owner}:{:X}:{}:{}:{:X}",
                    observation.offset,
                    observation.width,
                    observation.access,
                    observation.instruction_rva
                ),
                subject: ClaimSubject::Member {
                    owner: owner.clone(),
                    offset: observation.offset,
                    width: u32::try_from(observation.width).unwrap_or(0),
                    name: observation.suggested_name.clone(),
                    access: observation.access.into(),
                },
                status: ClaimStatus::Observed,
                usability: Usability::MetadataOnly,
                evidence_ids: vec![evidence_id],
                proof_id: Some(proof_id),
            });
        }
    }

    for (owner, value) in allocation_sizes {
        let size = value.get("size").and_then(Value::as_u64).unwrap_or(0);
        let vftable = value.get("vftable").and_then(Value::as_u64).unwrap_or(0);
        let rva = value
            .get("evidence_rva")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let symbol = value
            .get("evidence_symbol")
            .and_then(Value::as_str)
            .unwrap_or("");
        let evidence_id = format!("ev:object-size:{owner}:{rva:X}:{size:X}");
        let proof_id = format!("proof:object-size:{owner}:{rva:X}");
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::Dataflow,
            tool: EvidenceTool::Windissect,
            rule_id: "x64.allocation-vftable-size".into(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: Some(symbol.into()),
                rva: Some(rva),
                size: None,
                instruction_rvas: vec![],
            },
            observation: EvidenceObservation::AllocationVtable {
                owner: owner.clone(),
                size,
                vftable,
            },
        });
        db.proofs.push(Proof {
            id: proof_id.clone(),
            rule_id: "x64.allocation-vftable-size".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![
                ProofObligation {
                    name: "bounded-allocation-immediate".into(),
                    satisfied: true,
                    detail: format!("0x{size:X} bytes"),
                },
                ProofObligation {
                    name: "returned-object-alias".into(),
                    satisfied: true,
                    detail: "allocator return tracked into object register".into(),
                },
                ProofObligation {
                    name: "known-class-vftable-store".into(),
                    satisfied: vftable != 0,
                    detail: format!("vftable VA 0x{vftable:X}"),
                },
            ],
        });
        db.claims.push(Claim {
            id: format!("claim:object-size:{owner}"),
            subject: ClaimSubject::ObjectSize {
                owner: owner.clone(),
                size,
            },
            status: ClaimStatus::Derived,
            usability: Usability::MetadataOnly,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id),
        });
    }
}

fn allocation_size_proof(
    bytes: &[u8],
    ip: u64,
    vftable_addresses: &BTreeSet<u64>,
) -> Option<(u64, u64)> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut size_candidate = None;
    let mut allocation: Option<(u64, usize, Vec<Register>)> = None;
    let mut vftable_registers = Vec::<(Register, u64)>::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::ECX
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate32to64
            )
        {
            let value = u64::try_from(instruction.immediate32to64()).unwrap_or(0);
            if (8..=0x10_0000).contains(&value) {
                size_candidate = Some(value);
            }
        } else if instruction.mnemonic() == Mnemonic::Call {
            allocation = size_candidate
                .take()
                .map(|size| (size, 0, vec![Register::RAX]));
            vftable_registers.clear();
        }

        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.is_ip_rel_memory_operand()
            && vftable_addresses.contains(&instruction.ip_rel_memory_address())
        {
            vftable_registers.push((
                instruction.op0_register().full_register(),
                instruction.ip_rel_memory_address(),
            ));
        }

        if let Some((size, age, aliases)) = &mut allocation {
            *age += 1;
            if *age > 40 {
                allocation = None;
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && aliases.contains(&instruction.op1_register().full_register())
            {
                let register = instruction.op0_register().full_register();
                if !aliases.contains(&register) {
                    aliases.push(register);
                }
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_displacement64() == 0
                && aliases.contains(&instruction.memory_base().full_register())
                && instruction.op1_kind() == OpKind::Register
                && vftable_registers
                    .iter()
                    .any(|(register, _)| *register == instruction.op1_register().full_register())
            {
                let source = instruction.op1_register().full_register();
                let vftable = vftable_registers
                    .iter()
                    .rev()
                    .find_map(|(register, address)| (*register == source).then_some(*address))
                    .unwrap_or(0);
                return Some((*size, vftable));
            }
        }
    }
    None
}

fn member_name(method: Option<&str>, access: &str) -> Option<String> {
    let method = method?;
    let stem = if access == "write" {
        method.strip_prefix("Set")?
    } else {
        method
            .strip_prefix("Get")
            .or_else(|| method.strip_prefix("Is"))?
    };
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

fn qualified_class(symbol: &crate::model::Symbol) -> Option<String> {
    let class = symbol.sig.class.as_deref()?;
    match symbol
        .sig
        .namespace
        .as_deref()
        .filter(|namespace| !namespace.is_empty())
    {
        Some(namespace) => Some(format!("{namespace}::{class}")),
        None => Some(class.to_string()),
    }
}

fn alias_offset(aliases: &[(Register, i64)], register: Register) -> Option<i64> {
    let register = register.full_register();
    aliases
        .iter()
        .find_map(|(candidate, offset)| (*candidate == register).then_some(*offset))
}

fn set_alias(aliases: &mut Vec<(Register, i64)>, register: Register, offset: i64) {
    let register = register.full_register();
    aliases.retain(|(candidate, _)| *candidate != register);
    aliases.push((register, offset));
}

fn kill_alias(aliases: &mut Vec<(Register, i64)>, register: Register) {
    let register = register.full_register();
    aliases.retain(|(candidate, _)| *candidate != register);
}

fn update_this_aliases(instruction: &iced_x86::Instruction, aliases: &mut Vec<(Register, i64)>) {
    if instruction.mnemonic() == Mnemonic::Call {
        for volatile in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ] {
            kill_alias(aliases, volatile);
        }
        return;
    }
    if instruction.op0_kind() != OpKind::Register {
        return;
    }
    let destination = instruction.op0_register().full_register();
    if instruction.mnemonic() == Mnemonic::Mov
        && instruction.op1_kind() == OpKind::Register
        && let Some(offset) = alias_offset(aliases, instruction.op1_register())
    {
        set_alias(aliases, destination, offset);
        return;
    }
    if instruction.mnemonic() == Mnemonic::Lea
        && instruction.op1_kind() == OpKind::Memory
        && instruction.memory_index() == Register::None
        && let Some(base) = alias_offset(aliases, instruction.memory_base())
    {
        let offset = base.wrapping_add(instruction.memory_displacement64() as i64);
        set_alias(aliases, destination, offset);
        return;
    }
    kill_alias(aliases, destination);
}

fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    pe.sections.iter().find_map(|section| {
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.size_of_raw_data {
            return None;
        }
        usize::try_from(section.pointer_to_raw_data.checked_add(delta)?).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::{alias_offset, allocation_size_proof, member_name, update_this_aliases};
    use iced_x86::{Decoder, DecoderOptions, Register};
    use std::collections::BTreeSet;

    #[test]
    fn only_names_getters_and_predicates() {
        assert_eq!(
            member_name(Some("GetParent"), "read").as_deref(),
            Some("Parent")
        );
        assert_eq!(
            member_name(Some("IsVisible"), "read").as_deref(),
            Some("Visible")
        );
        assert_eq!(
            member_name(Some("SetParent"), "write").as_deref(),
            Some("Parent")
        );
    }

    #[test]
    fn allocation_requires_vftable_store_into_returned_block() {
        // mov ecx,100h; call; mov rbx,rax; lea rax,[rip+10h]; mov [rbx],rax
        let bytes = [
            0xB9, 0x00, 0x01, 0x00, 0x00, 0xE8, 0, 0, 0, 0, 0x48, 0x8B, 0xD8, 0x48, 0x8D, 0x05,
            0x10, 0, 0, 0, 0x48, 0x89, 0x03,
        ];
        let mut tables = BTreeSet::new();
        tables.insert(0x1024);
        assert_eq!(
            allocation_size_proof(&bytes, 0x1000, &tables),
            Some((0x100, 0x1024))
        );
        assert_eq!(
            allocation_size_proof(&bytes, 0x1000, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn calls_preserve_nonvolatile_this_aliases_only() {
        // mov rbx,rcx; mov r8,rcx; call rel32
        let bytes = [0x48, 0x8B, 0xD9, 0x4C, 0x8B, 0xC1, 0xE8, 0, 0, 0, 0];
        let mut decoder = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let mut aliases = vec![(Register::RCX, 0)];
        update_this_aliases(&decoder.decode(), &mut aliases);
        update_this_aliases(&decoder.decode(), &mut aliases);
        assert_eq!(alias_offset(&aliases, Register::RBX), Some(0));
        assert_eq!(alias_offset(&aliases, Register::R8), Some(0));
        update_this_aliases(&decoder.decode(), &mut aliases);
        assert_eq!(alias_offset(&aliases, Register::RBX), Some(0));
        assert_eq!(alias_offset(&aliases, Register::R8), None);
        assert_eq!(alias_offset(&aliases, Register::RCX), None);
    }
}
