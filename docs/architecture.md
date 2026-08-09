# Architecture

Windissect separates evidence collection from claims and callable output. A
name or instruction observation does not become a usable declaration unless
the relevant proof obligations pass.

```mermaid
flowchart LR
    A[Windows DLL / EXE / SYS] --> B[PE parser]
    P[Identity-matched PDB] --> C[PDB symbols and types]
    B --> D[Normalized schema-v2 IR]
    C --> D
    O[Optional IDA / r2 observations] --> E[Evidence importer]
    E --> D
    D --> F[Architecture-aware disassembly]
    D --> G[RTTI, layout, reflection analyzers]
    F --> H[Evidence, claims, proofs, conflicts]
    G --> H
    H --> V{Verification gate}
    V -->|verified| I[C / C++ / Rust / docs]
    V -->|unresolved| J[Metadata and annotated assembly]
    D --> K[Per-build archive]
    K --> L[Semantic build diff]
```

The central invariant is that uncertainty remains visible. Unsupported
architectures, mismatched PDBs, signature conflicts, and heuristic layout
observations are rejected or emitted as metadata rather than being presented
as callable interfaces.

## Pipeline boundaries

- `extract` establishes binary identity, reads PE/PDB records, and runs static
  analyzers.
- Schema-v2 IR retains observations, claims, proof obligations, conflicts, and
  capability outcomes independently.
- `verify` checks graph integrity and generic invariants; optional profiles add
  target-specific ground-truth checks.
- Emitters consume the IR and separate verified surfaces from experimental or
  metadata-only results.
- `record-build` stores immutable snapshots and produces adjacent semantic
  JSON and Markdown diffs.

