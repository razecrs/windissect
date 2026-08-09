# Output status

Windissect uses two independent labels: epistemic status (what the evidence
supports) and usability (what an emitter may safely expose).

## Verified

- PE/PDB identity and binary build anchors
- exports, ordinals, forwarders, and identity-matched PDB procedure names
- schema-v2 graph integrity and satisfied proof obligations
- architecture-aware x86/x64 instruction decoding
- compatible vftable slots and explicitly supported call helpers
- artifacts written by `emit-evidence` to `verified.json`

## Experimental or metadata-only

- heuristic member offsets without a certified cross-binary evidence pack
- reflection-property observations that have not been corroborated
- template-derived base candidates without proven offsets
- incompatible ICF/vftable candidates
- imported IDA/r2 observations before an analyzer proves the corresponding
  high-level claim
- ARM64, ARM64EC, and SYS-specific semantic recovery

Experimental data remains useful for reversing and annotated assembly, but it
must not be described as an ABI-safe declaration.

