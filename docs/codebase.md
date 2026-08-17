# Codebase map

Windissect is split into extraction, analysis, proof, emission, and fleet
orchestration layers.

| Module | Responsibility |
|---|---|
| `main.rs` | CLI dispatch for extraction, verification, emission, documentation, diffs, history, evidence packs, oracle imports, refinement, and semantic scoring |
| `extract.rs`, `pdbsym.rs`, `pdbtype.rs` | PE identity/exports and identity-matched PDB symbols, procedures, and type records |
| `demangle.rs`, `typeparse.rs` | MSVC declaration demangling and structured type parsing |
| `enrich.rs` | Architecture-aware function boundaries, instructions, hashes, calls, thunks, and imports |
| `rtti.rs`, `layoutinfer.rs`, `reflection.rs` | PE-native vftables, conservative member observations, allocation sizes, and reflection metadata |
| `model.rs` | Schema-v3 evidence, claims, proofs, conflicts, capabilities, symbols, types, semantic facts, and canonical instruction records |
| `verify.rs` | Generic graph/identity/proof invariants and optional target profiles |
| `emit.rs`, `emit_rust.rs`, `emit_syms.rs` | C/C++ declarations, proof-gated callable helpers, Rust output, and C symbol tables |
| `emit_evidence.rs`, `emit_asm.rs`, `docs.rs` | Separated evidence surfaces, annotated assembly, and Markdown references |
| `diff.rs`, `history.rs` | Semantic build comparison and immutable per-build archives |
| `evidencepack.rs`, `oracle.rs` | Manual-rule corpus validation and binary-identity-checked IDA/r2 observation imports |
| `refine.rs` | Reference-corpus gap analysis, indexed proof-gated recovery jobs, and target-neutral PDB callable recovery |
| `semantic.rs`, `semantic_emit.rs` | Proof-gated semantic projection and separate verified/candidate C++/Rust output |
| `semantic_validate.rs`, `semantic_score.rs` | Compiler roundtrips and exact-build precision/recall scoring |
| `semantic_probe.rs` | Opt-in isolated DLL probe with exact-hash and proof-manifest gates |
| `cmd/windissect` | Multi-target discovery, symbol-server retrieval, caching, extraction, history, and emission |

## Trust boundary

PE and PDB records enter the normalized IR as observations. An analyzer may
derive a claim and its proof obligations, but a verified usability label is
accepted only when evidence exists, the referenced proof passes every
obligation, and no unresolved conflict names the claim. Callable C++ and Rust
surfaces additionally require verified addressability and signature claims for
the same symbol. Unproven data remains available through metadata, evidence,
and annotated assembly outputs.

## CLI surfaces

- `extract`, `verify`, and `classes`
- `emit-cpp`, `emit-headers`, `emit-rust`, `emit-syms`
- `emit-evidence`, `emit-asm`, and `doc`
- `diff` and `record-build`
- `validate-evidence-pack` and `import-oracle`
- `refine --semantic` and `score-semantic`
