# Output status

Windissect uses two independent labels: epistemic status (what the evidence
supports) and usability (what an emitter may safely expose).

## Verified

- PE/PDB identity and binary build anchors
- exports, ordinals, forwarders, and identity-matched PDB procedure names
- schema-v3 graph integrity and satisfied proof obligations
- architecture-aware x86/x64 instruction decoding
- compatible vftable slots and explicitly supported call helpers
- artifacts written by `emit-evidence` to `verified.json`
- identity-matched full-PDB class sizes, field widths/offsets, bitfields,
  inheritance offsets, virtual-slot order, and enum values/underlying types
  after semantic compiler validation
- the primary generated `<target>.h`, which contains only verified ABI
  metadata and proof-gated call/vcall helpers

## Experimental or metadata-only

- heuristic member offsets without a certified cross-binary evidence pack
- reflection-property observations that have not been corroborated
- template-derived base candidates without proven offsets
- incompatible ICF/vftable candidates
- imported IDA/r2 observations before an analyzer proves the corresponding
  high-level claim
- CodeView aliases (`LF_ALIAS`) until parser support is added
- ARM64 and ARM64EC semantic recovery
- SYS runtime probing; SYS static extraction and semantic emission are supported
- exhaustive `<target>_candidates.h` class declarations until their individual
  language, ownership, layout, and signature obligations are proven

Experimental data remains useful for reversing and annotated assembly, but it
must not be described as an ABI-safe declaration.
