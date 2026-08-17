# WinDissect tool study set

These are shallow, read-only Git snapshots selected to study implementation techniques, not copied answer corpora. `manifest.json` records the exact repository URL and commit used.

| Area | Study repository | What to inspect |
|---|---|---|
| PE/COFF parsing | trailofbits/pe-parse, m4b/goblin | section bounds, exports, relocations, CodeView identity |
| PDB/MSF and UDTs | microsoft/pdb-rs, getsentry/pdb, moyix/pdbparse, nikgeneburn/MemPDB, nikaiw/pdbinspector | symbol streams, type records, procedures, layouts, GUID+age |
| Instruction decoding | icedland/iced, capstone-engine/capstone | flow control, operands, displacement metadata, architecture dispatch |
| Full reverse engineering | NSA/ghidra, avast/retdec | function recovery, type propagation, decompilation, automation workflows |
| Binary diffing | joxeankoret/diaphora | function matching, structural similarity, version comparisons |

The two initially guessed URLs that did not exist were not retained: `0xazure/pdb` and `rocky/python-diaphora`. Their replacements are recorded above.

Study order for Windissect:

1. PDB UDT/procedure extraction and exact identity validation.
2. Iced/Capstone operand and relocation metadata for independent field/vtable evidence.
3. Ghidra/RetDec recovery heuristics as optional cross-checks.
4. Diaphora matching ideas for build-to-build semantic diffs.
5. PE parser edge cases and SYS/EXE handling.

No repository is treated as proof of a target DLL's private interface. External declarations remain hypotheses until independently supported by the target binary, PDB, runtime, or explicit evidence.
