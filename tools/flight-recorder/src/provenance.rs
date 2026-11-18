pub struct ExpectedModule {
    pub name: &'static str,
    pub timestamp: u32,
    pub pdb_guid: &'static str,
    pub pdb_age: u32,
}

pub const MODULES: &[ExpectedModule] = &[
    ExpectedModule {
        name: "dxgi.dll",
        timestamp: windissect_dxgi::EXPECTED_PE_TIMESTAMP,
        pdb_guid: windissect_dxgi::EXPECTED_PDB_GUID,
        pdb_age: windissect_dxgi::EXPECTED_PDB_AGE,
    },
    ExpectedModule {
        name: "d3d11.dll",
        timestamp: windissect_d3d11::EXPECTED_PE_TIMESTAMP,
        pdb_guid: windissect_d3d11::EXPECTED_PDB_GUID,
        pdb_age: windissect_d3d11::EXPECTED_PDB_AGE,
    },
    ExpectedModule {
        name: "mfplat.dll",
        timestamp: windissect_mfplat::EXPECTED_PE_TIMESTAMP,
        pdb_guid: windissect_mfplat::EXPECTED_PDB_GUID,
        pdb_age: windissect_mfplat::EXPECTED_PDB_AGE,
    },
    ExpectedModule {
        name: "mfreadwrite.dll",
        timestamp: windissect_mfreadwrite::EXPECTED_PE_TIMESTAMP,
        pdb_guid: windissect_mfreadwrite::EXPECTED_PDB_GUID,
        pdb_age: windissect_mfreadwrite::EXPECTED_PDB_AGE,
    },
];

pub fn print_manifest() {
    eprintln!("Windissect ABI provenance:");
    for module in MODULES {
        eprintln!(
            "  {:<18} PE timestamp {:08X}, PDB {}-{}",
            module.name, module.timestamp, module.pdb_guid, module.pdb_age
        );
    }
}

