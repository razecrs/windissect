//! PE export and PDB internal symbol extractor. See `docs/codebase.md#2-extractrs` or `cargo doc`.

use crate::model::{BinaryInfo, Confidence, Coverage, Kind, Provenance, Symbol};
use anyhow::{Context, Result};
use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct Extracted {
    pub symbols: Vec<Symbol>,
    pub info: BinaryInfo,
    pub pdb_coverage: Option<serde_json::Value>,
    pub pdb_records: Vec<serde_json::Value>,
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
        sig: crate::model::Signature::default(),
        callers: vec![],
        calls: vec![],
        imports: vec![],
    }
}

pub fn from_pe(dll: &Path, pdb: Option<&Path>, retain_pdb_records: bool) -> Result<Extracted> {
    let bytes = std::fs::read(dll).with_context(|| format!("read {}", dll.display()))?;
    let pe = PE::parse(&bytes).context("parse PE")?;
    let base = pe.image_base as u64;
    let (symbols, export_rvas) = extract_exports(&pe, base);
    let (pdb_symbols, pdb_coverage, pdb_records) =
        merge_pdb(&pe, pdb, base, &export_rvas, retain_pdb_records)?;
    let symbols = merge_exact_symbols(symbols, pdb_symbols);
    let info = binary_info(dll, &bytes, &pe, base);
    Ok(Extracted {
        symbols,
        info,
        pdb_coverage,
        pdb_records,
    })
}

fn extract_exports(pe: &PE<'_>, base: u64) -> (Vec<Symbol>, BTreeSet<u32>) {
    let mut symbols = Vec::new();
    let mut export_rvas = BTreeSet::new();
    let ordinal_base = pe
        .export_data
        .as_ref()
        .map_or(0, |d| d.export_directory_table.ordinal_base);
    let export_ordinals = pe.export_data.as_ref().map(|d| &d.export_ordinal_table);
    let mut named_ordinals = BTreeSet::new();
    for (index, e) in pe.exports.iter().enumerate() {
        let Ok(default_ordinal_index) = u16::try_from(index) else {
            continue;
        };
        let ordinal_index = export_ordinals
            .and_then(|items| items.get(index))
            .copied()
            .unwrap_or(default_ordinal_index);
        named_ordinals.insert(ordinal_index);
        let ordinal = ordinal_base + u32::from(ordinal_index);
        let owned_name = e
            .name
            .map_or_else(|| format!("#ordinal{ordinal}"), str::to_owned);
        let name = owned_name.as_str();
        let Ok(rva) = u32::try_from(e.rva) else {
            continue;
        };
        export_rvas.insert(rva);
        let mut symbol = blank(
            name.to_string(),
            name.to_string(),
            base + u64::from(rva),
            true,
            Provenance::PeExport,
        );
        symbol.rva = rva;
        symbol.ordinal = Some(ordinal);
        symbol.is_code = e.reexport.is_none() && rva_is_executable(pe, rva);
        symbol.forwarder = e.reexport.as_ref().map(|r| format!("{r:?}"));
        symbols.push(symbol);
    }
    if let Some(data) = &pe.export_data {
        use goblin::pe::export::ExportAddressTableEntry;
        for (index, entry) in data.export_address_table.iter().enumerate() {
            let Ok(ordinal_index) = u16::try_from(index) else {
                continue;
            };
            if named_ordinals.contains(&ordinal_index) {
                continue;
            }
            let Ok(index_u32) = u32::try_from(index) else {
                continue;
            };
            let ordinal = ordinal_base + index_u32;
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
            symbol.is_code = forwarder.is_none() && rva_is_executable(pe, rva);
            symbol.forwarder = forwarder;
            export_rvas.insert(rva);
            symbols.push(symbol);
        }
    }

    (symbols, export_rvas)
}

fn rva_is_executable(pe: &PE<'_>, rva: u32) -> bool {
    pe.sections.iter().any(|section| {
        let extent = section.virtual_size.max(section.size_of_raw_data);
        rva >= section.virtual_address
            && rva < section.virtual_address.saturating_add(extent)
            && section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
    })
}

fn merge_exact_symbols(exports: Vec<Symbol>, pdb_symbols: Vec<Symbol>) -> Vec<Symbol> {
    let mut merged = BTreeMap::<(u32, String), Symbol>::new();
    for symbol in exports {
        merged.insert((symbol.rva, symbol.mangled.clone()), symbol);
    }
    for mut symbol in pdb_symbols {
        let key = (symbol.rva, symbol.mangled.clone());
        if let Some(export) = merged.remove(&key) {
            symbol.exported |= export.exported;
            symbol.ordinal = symbol.ordinal.or(export.ordinal);
            symbol.forwarder = symbol.forwarder.or(export.forwarder);
            if symbol.size == 0 {
                symbol.size = export.size;
            }
        }
        merged.insert(key, symbol);
    }
    merged.into_values().collect()
}

fn merge_pdb(
    pe: &PE<'_>,
    pdb: Option<&Path>,
    base: u64,
    export_rvas: &BTreeSet<u32>,
    retain_records: bool,
) -> Result<(
    Vec<Symbol>,
    Option<serde_json::Value>,
    Vec<serde_json::Value>,
)> {
    let Some(pdb_path) = pdb else {
        return Ok((Vec::new(), None, Vec::new()));
    };
    let pdb_data = crate::pdbsym::read(pdb_path, retain_records)?;
    let coverage = Some(serde_json::json!({
            "procedures": pdb_data.coverage.procedures,
            "thunks": pdb_data.coverage.thunks,
            "locals": pdb_data.coverage.locals,
            "blocks": pdb_data.coverage.blocks,
            "inline_sites": pdb_data.coverage.inline_sites,
            "data_symbols": pdb_data.coverage.data_symbols,
            "tls_symbols": pdb_data.coverage.tls_symbols,
            "constants": pdb_data.coverage.constants,
            "build_info": pdb_data.coverage.build_info,
            "annotations": pdb_data.coverage.annotations
            ,"source_lines": pdb_data.coverage.source_lines
    }));
    let dbg = pe
        .debug_data
        .as_ref()
        .and_then(|data| data.codeview_pdb70_debug_info.as_ref())
        .context("cannot prove PDB identity: PE has no RSDS CodeView record")?;
    let expected = codeview_guid(&dbg.signature);
    anyhow::ensure!(
        pdb_data.guid == expected && pdb_data.age == dbg.age,
        "PDB identity mismatch: PE expects {expected}+{:X}, PDB is {}+{:X}",
        dbg.age,
        pdb_data.guid,
        pdb_data.age
    );
    let symbols = pdb_data
        .symbols
        .into_iter()
        .map(|symbol| {
            let mut record = blank(
                symbol.name.clone(),
                symbol.name,
                base + u64::from(symbol.rva),
                false,
                Provenance::Pdb,
            );
            record.rva = symbol.rva;
            record.size = symbol.size;
            record.procedure_size = (symbol.function && symbol.size != 0).then_some(symbol.size);
            record.is_code = symbol.function;
            record.exported = export_rvas.contains(&symbol.rva);
            record
        })
        .collect();
    Ok((symbols, coverage, pdb_data.records))
}

fn binary_info(dll: &Path, bytes: &[u8], pe: &PE<'_>, base: u64) -> BinaryInfo {
    let mut info = BinaryInfo {
        file: dll
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        timestamp: Some(pe.header.coff_header.time_date_stamp.to_string()),
        sha256: Some(crate::hex::lower(&Sha256::digest(bytes))),
        machine: Some(format!("0x{:04x}", pe.header.coff_header.machine)),
        image_base: Some(base),
        image_size: pe
            .header
            .optional_header
            .as_ref()
            .map(|header| u64::from(header.windows_fields.size_of_image)),
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

    info
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
        crate::hex::upper(&g[8..])
    )
}

#[cfg(test)]
mod tests {
    use super::{blank, merge_exact_symbols};
    use crate::model::Provenance;

    #[test]
    fn pdb_data_identity_replaces_export_code_guess() {
        let mut export = blank(
            "??_7Widget@@6B@".into(),
            "??_7Widget@@6B@".into(),
            0x1800_2000,
            true,
            Provenance::PeExport,
        );
        export.rva = 0x2000;
        export.ordinal = Some(7);
        export.is_code = true;
        let mut pdb = blank(
            "??_7Widget@@6B@".into(),
            "??_7Widget@@6B@".into(),
            0x1800_2000,
            false,
            Provenance::Pdb,
        );
        pdb.rva = 0x2000;

        let merged = merge_exact_symbols(vec![export], vec![pdb]);

        assert_eq!(merged.len(), 1);
        assert!(merged[0].exported);
        assert_eq!(merged[0].ordinal, Some(7));
        assert!(!merged[0].is_code);
    }
}
