//! PE export and PDB internal symbol extractor. See `docs/codebase.md#2-extractrs` or `cargo doc`.

use crate::model::{BinaryInfo, Confidence, Coverage, Kind, Provenance, Symbol};
use anyhow::{Context, Result};
use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

pub struct Extracted {
    pub symbols: Vec<Symbol>,
    pub info: BinaryInfo,
}

/// Creates a symbol shell with default flags. See `docs/codebase.md#2-extractrs`.
fn blank(id: String, mangled: String, vaddr: u64, exported: bool, prov: Provenance) -> Symbol {
    Symbol {
        id,
        mangled,
        demangled: None,
        vaddr,
        rva: 0,
        ordinal: None,
        size: 0,
        procedure_size: None,
        is_code: false,
        forwarder: None,
        body_hash: String::new(),
        exported,
        library: false,
        kind: Kind::Unknown,
        coverage: Coverage::Auto,
        provenance: prov,
        confidence: Confidence::Certain,
        sig: Default::default(),
        callers: vec![],
        calls: vec![],
        imports: vec![],
    }
}

pub fn from_pe(dll: &Path, pdb: Option<&Path>) -> Result<Extracted> {
    let bytes = std::fs::read(dll).with_context(|| format!("read {}", dll.display()))?;
    let pe = PE::parse(&bytes).context("parse PE")?;
    let base = pe.image_base as u64;

    let mut symbols = Vec::new();
    let mut export_rvas: BTreeSet<u32> = BTreeSet::new();
    let ordinal_base = pe
        .export_data
        .as_ref()
        .map(|d| d.export_directory_table.ordinal_base)
        .unwrap_or(0);
    let export_ordinals = pe.export_data.as_ref().map(|d| &d.export_ordinal_table);
    let mut named_ordinals = BTreeSet::new();
    for (index, e) in pe.exports.iter().enumerate() {
        let ordinal_index = export_ordinals
            .and_then(|items| items.get(index))
            .copied()
            .unwrap_or(index as u16);
        named_ordinals.insert(ordinal_index);
        let ordinal = ordinal_base + u32::from(ordinal_index);
        let owned_name = e
            .name
            .map(str::to_owned)
            .unwrap_or_else(|| format!("#ordinal{ordinal}"));
        let name = owned_name.as_str();
        export_rvas.insert(e.rva as u32);
        let mut symbol = blank(
            name.to_string(),
            name.to_string(),
            base + e.rva as u64,
            true,
            Provenance::PeExport,
        );
        symbol.rva = e.rva as u32;
        symbol.ordinal = Some(ordinal);
        symbol.is_code = e.reexport.is_none();
        symbol.forwarder = e.reexport.as_ref().map(|r| format!("{r:?}"));
        symbols.push(symbol);
    }
    if let Some(data) = &pe.export_data {
        use goblin::pe::export::ExportAddressTableEntry;
        for (index, entry) in data.export_address_table.iter().enumerate() {
            if named_ordinals.contains(&(index as u16)) {
                continue;
            }
            let ordinal = ordinal_base + index as u32;
            let (rva, forwarder) = match entry {
                ExportAddressTableEntry::ExportRVA(rva) => (*rva, None),
                ExportAddressTableEntry::ForwarderRVA(rva) => (*rva, Some("<forwarded>".into())),
            };
            if rva == 0 {
                continue;
            }
            let name = format!("#ordinal{ordinal}");
            let mut symbol = blank(
                name.clone(),
                name,
                base + u64::from(rva),
                true,
                Provenance::PeExport,
            );
            symbol.rva = rva;
            symbol.ordinal = Some(ordinal);
            symbol.is_code = forwarder.is_none();
            symbol.forwarder = forwarder;
            export_rvas.insert(rva);
            symbols.push(symbol);
        }
    }

    // Merge internal functions the PDB names but exports can't reach.
    if let Some(pdb_path) = pdb {
        let pdb_data = crate::pdbsym::read(pdb_path)?;
        let dbg = pe
            .debug_data
            .as_ref()
            .and_then(|d| d.codeview_pdb70_debug_info.as_ref())
            .context("cannot prove PDB identity: PE has no RSDS CodeView record")?;
        let expected = codeview_guid(&dbg.signature);
        anyhow::ensure!(
            pdb_data.guid == expected && pdb_data.age == dbg.age,
            "PDB identity mismatch: PE expects {expected}+{:X}, PDB is {}+{:X}",
            dbg.age,
            pdb_data.guid,
            pdb_data.age
        );
        for sym in pdb_data.symbols {
            if !sym.function {
                continue;
            }
            let mut record = blank(
                sym.name.clone(),
                sym.name,
                base + sym.rva as u64,
                false,
                Provenance::Pdb,
            );
            record.rva = sym.rva;
            record.size = sym.size;
            record.procedure_size = (sym.size != 0).then_some(sym.size);
            record.is_code = true;
            if export_rvas.contains(&sym.rva) {
                record.exported = true;
            }
            symbols.push(record);
        }
    }

    let mut info = BinaryInfo {
        file: dll
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        timestamp: Some(pe.header.coff_header.time_date_stamp.to_string()),
        sha256: Some(
            Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
        machine: Some(format!("0x{:04x}", pe.header.coff_header.machine)),
        image_base: Some(base),
        ..Default::default()
    };
    if let Some(dbg) = pe
        .debug_data
        .as_ref()
        .and_then(|d| d.codeview_pdb70_debug_info.as_ref())
    {
        info.pdb_name = Some(
            String::from_utf8_lossy(dbg.filename)
                .trim_end_matches('\0')
                .to_string(),
        );
        info.pdb_guid = Some(codeview_guid(&dbg.signature));
        info.pdb_age = Some(dbg.age);
    }

    Ok(Extracted { symbols, info })
}

fn codeview_guid(g: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{}",
        g[3],
        g[2],
        g[1],
        g[0],
        g[5],
        g[4],
        g[7],
        g[6],
        g[8..]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    )
}
