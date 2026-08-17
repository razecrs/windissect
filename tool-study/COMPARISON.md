# Tool-study comparison baseline

This comparison is based on the local shallow snapshots listed in `manifest.json` and the current Windissect source. Measured counts are in `measured-tools.json` and `windissect-measured.json`; they are file/text-hit counts, not quality scores.

## Measured baseline

Windissect source: 28 Rust files; 11 files mention procedure/thunk concepts; 1 mentions CodeView UDT leaf names; 12 mention vtable concepts.

Selected local snapshots:

- `getsentry-pdb`: 60 files, 37 Rust; 12 procedure-hit files, 5 UDT-hit files, 3 vtable-hit files.
- `microsoft-pdb-rs`: 227 files, 127 Rust; 42 procedure-hit files, 15 UDT-hit files, 13 vtable-hit files.
- `mempdb`: 24 files, 16 C/C++; 2 procedure-hit files, 4 UDT-hit files, 11 vtable-hit files.
- `pdbparse`: 35 files, 27 Python; 5 procedure-hit files, 7 UDT-hit files, 2 vtable-hit files.
- `diaphora`: 371 files, 330 Python; 34 procedure-hit files and 5 vtable-hit files.

These counts show where implementation surface exists; they do not establish which project is more accurate.

| Capability | Windissect now | Strongest local reference | Current assessment |
|---|---|---|---|
| PE metadata/exports | Rust extraction, identity, sections, exports, imports | goblin / pe-parse | Windissect already has the needed model; compare edge-case handling before changing it. |
| x86/x64 decoding | iced-backed enrichment with architecture checks | iced | Windissect benefits from iced's operand/flow metadata; no wholesale replacement needed. |
| PDB global symbols | Existing extraction and identity checks | getsentry/pdb, pdbinspector | Windissect needs broader stream traversal and richer symbol retention. `getsentry-pdb/examples/pdb_symbols.rs` demonstrates procedure records; `src/pdbsym.rs` is the Windissect comparison point. |
| Private/module procedures | Partial | getsentry/pdb `Procedure`/`Thunk` records; pdbinspector module reports | Clear Windissect gap: enumerate DBI modules and procedure records instead of globals only. |
| UDT field lists | Existing parser/projection, limited promotion | pdbparse `examples/pdb_print_ctypes.py`; getsentry `examples/pdb2hpp.rs`; MemPDB `tools/pdb2json` | Windissect has evidence gating; references provide parsing patterns, not facts. |
| Vtable symbols | RTTI/vtable analysis exists | MemPDB `include/MemPDB/MemPDB.hpp`; Ghidra RTTI workflows | Add independent vtable-symbol indexing and cross-check it against disassembly. |
| Field offsets | Manual/exact evidence plus semantic emitter | pdbparse ctypes reconstruction | Windissect is stronger on provenance; weaker on automatic complete field-list recovery. |
| Function recovery | PDB/export/enrichment pipeline | Ghidra / RetDec | External tools have broader heuristics; Windissect is more evidence-explicit. |
| Version diffing | Build archive and semantic diff model | Diaphora | Windissect is better for typed, identity-anchored output; Diaphora is stronger for function matching. |
| Rust output | Generic candidate/verified semantic Rust emitter | microsoft/pdb-rs is a parser, not a comparable binding emitter | Windissect has the relevant output advantage; ABI proof remains the priority. |
| C/C++ output | Generic headers plus semantic layouts | pdbparse examples can print declarations | Windissect has stronger status/provenance separation; external printers are useful cross-checks. |

## What we should study, not blindly copy

1. Port the DBI-module and `Procedure`/`Thunk` traversal pattern from the Rust PDB readers into Windissect's own model.
2. Port the CodeView `LF_STRUCTURE`/`LF_FIELDLIST`/`LF_MEMBER` closure logic from the PDB readers, preserving exact record IDs and evidence locations.
3. Port MemPDB's explicit symbol-kind separation so vtables, RTTI, strings, variables, and procedures cannot be conflated.
4. Use Ghidra/RetDec only as optional independent heuristic oracles; never promote their output without target evidence.
5. Study Diaphora's function-matching features for Windissect's typed build diff, while retaining PE/PDB identity anchoring.
6. Keep Windissect's evidence/proof gates, candidate separation, target-generic model, and C/Rust status-aware emission as the controlling architecture.

## Decision rule

For each proposed import, we will record: external algorithm, Windissect equivalent, measured accuracy on a fixture, performance cost, false-positive behavior, and whether it preserves provenance. An idea is adopted only if it improves a measured Windissect weakness without weakening proof status.
