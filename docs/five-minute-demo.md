# Five-minute demonstration

## Fast target-independent run

On Windows with Rust installed:

```powershell
pwsh -File scripts/demo.ps1
```

The script builds Windissect, analyzes the installed `amsi.dll` without a PDB,
verifies the schema-v2 IR, and emits evidence, C/C++ headers, a C symbol table,
and a Rust crate under `target/demo/amsi/`. AMSI is intentionally unrelated to
DirectUI. This run validates the generic PE/export path; it does not claim
private type recovery without an identity-matched PDB.

## Deep DUI70 case

Microsoft binaries and PDBs are not redistributed. With an exact matching pair:

```powershell
cargo run --release -- extract .\dui70.dll --pdb .\DUI70.pdb --out target\demo\dui70.json
cargo run --release -- verify --ir target\demo\dui70.json --profile dui70
cargo run --release -- emit-evidence --ir target\demo\dui70.json --out target\demo\dui70-evidence
```

The verified v0.1.0 corpus contains 12,672 symbols, 2,690 evidence records,
2,690 claims, 2,345 proofs, 39 explicit conflicts, 150 PE-native vftables, and
1,870 exact-build member-access observations.

