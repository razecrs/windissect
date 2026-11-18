//! Annotated assembly fallback for functions without safe high-level bindings.

use crate::diff::atomic_write;
use crate::model::Database;
use anyhow::Result;
use std::fmt::Write;
use std::path::Path;

pub fn emit(db: &Database, out: &Path) -> Result<()> {
    let mut text = String::new();
    writeln!(text, "; Windissect canonical disassembly. DO NOT EDIT")?;
    writeln!(text, "; binary: {}", db.binary.file)?;
    writeln!(
        text,
        "; sha256: {}",
        db.binary.sha256.as_deref().unwrap_or("unknown")
    )?;
    writeln!(
        text,
        "; machine: {}\n",
        db.binary.machine.as_deref().unwrap_or("unknown")
    )?;
    for function in &db.functions {
        writeln!(
            text,
            "; ----------------------------------------------------------------"
        )?;
        writeln!(
            text,
            "; RVA 0x{:08X}, size 0x{:X}, symbols: {}",
            function.rva,
            function.size,
            function.symbol_ids.join(" | ")
        )?;
        writeln!(text, "windissect_{:08X}:", function.rva)?;
        for instruction in &function.instructions {
            write!(
                text,
                "    ; {:08X}  {:<30} {}",
                instruction.rva, instruction.bytes, instruction.text
            )?;
            if let Some(target) = instruction.branch_target_rva {
                write!(text, "  ; branch -> RVA 0x{target:08X}")?;
            }
            if let Some(target) = instruction.memory_target_rva {
                write!(text, "  ; data -> RVA 0x{target:08X}")?;
            }
            writeln!(text)?;
            if let Some(data) = &instruction.data_reference {
                writeln!(
                    text,
                    "    ;   Data reference: 0x{:X} (RVA 0x{:08X})",
                    data.virtual_address, data.rva
                )?;
                writeln!(
                    text,
                    "    ;   Section: {} | file offset 0x{:X}",
                    data.section, data.file_offset
                )?;
                if let Some(size) = data.inferred_size {
                    writeln!(
                        text,
                        "    ;   Size: {} bytes ({}; evidence RVA 0x{:08X})",
                        size,
                        data.size_source.as_deref().unwrap_or("code-inferred bound"),
                        data.size_evidence_rva.unwrap_or(0)
                    )?;
                } else {
                    writeln!(
                        text,
                        "    ;   Preview: {} bytes (object size unresolved; section-bounded)",
                        data.preview_size
                    )?;
                }
                writeln!(
                    text,
                    "    ;   Bytes: {}{}",
                    data.bytes,
                    if data.truncated { " …" } else { "" }
                )?;
            }
        }
        if !function.cfg_edges.is_empty() {
            writeln!(text, "    ; CFG edges:")?;
            for edge in &function.cfg_edges {
                writeln!(
                    text,
                    "    ;   {:08X} -> {:08X} ({})",
                    edge.from_rva, edge.to_rva, edge.kind
                )?;
            }
        }
        writeln!(text)?;
    }
    atomic_write(out, text.as_bytes())
}
