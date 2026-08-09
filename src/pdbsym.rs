//! Read function names + RVAs from a Microsoft PDB (the `pdb` crate).

use anyhow::{Context, Result};
use pdb::FallibleIterator;
use std::path::Path;

/// name + RVA + whether the symbol is a function, keyed for merging by RVA.
pub struct PdbSym {
    pub name: String,
    pub function: bool,
    pub rva: u32,
    pub size: u32,
}

pub struct PdbData {
    pub guid: String,
    pub age: u32,
    pub symbols: Vec<PdbSym>,
}

/// Returns public symbols plus private procedures from module streams.
pub fn read(path: &Path) -> Result<PdbData> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("open pdb")?;
    let info = pdb.pdb_information().context("pdb information")?;
    let guid = info.guid.as_simple().to_string().to_ascii_uppercase();
    // PE CodeView / symbol-server identity tracks the DBI age.  The PDB
    // information-stream age can legitimately differ (Microsoft's DUI70 PDB
    // is served under GUID+1 while its PDBI age is 3).
    let dbi = pdb.debug_information().context("debug information")?;
    let age = dbi.age().unwrap_or(info.age);
    let address_map = pdb.address_map().context("address map")?;

    let mut out = Vec::new();
    let globals = pdb.global_symbols().context("global symbols")?;
    let mut it = globals.iter();
    while let Some(sym) = it.next()? {
        if let Ok(pdb::SymbolData::Public(d)) = sym.parse()
            && let Some(rva) = d.offset.to_rva(&address_map)
        {
            out.push(PdbSym {
                name: d.name.to_string().into_owned(),
                function: d.function,
                rva: rva.0,
                size: 0,
            });
        }
    }

    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        let Some(module_info) = pdb.module_info(&module)? else {
            continue;
        };
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            if let Ok(pdb::SymbolData::Procedure(proc)) = symbol.parse()
                && let Some(rva) = proc.offset.to_rva(&address_map)
            {
                out.push(PdbSym {
                    name: proc.name.to_string().into_owned(),
                    function: true,
                    rva: rva.0,
                    size: proc.len,
                });
            }
        }
    }
    out.sort_by(|a, b| (a.rva, &a.name).cmp(&(b.rva, &b.name)));
    out.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
    Ok(PdbData {
        guid,
        age,
        symbols: out,
    })
}
