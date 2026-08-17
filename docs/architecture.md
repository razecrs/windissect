# Architecture

Windissect separates evidence collection from claims and callable output. A
name or instruction observation does not become a usable declaration unless
the relevant proof obligations pass.

```mermaid
flowchart LR
    A[Windows DLL / EXE / SYS] --> B[PE parser]
    P[Identity-matched PDB] --> C[PDB symbols and types]
    B --> D[Normalized schema-v3 IR]
    C --> D
    O[Optional IDA / r2 observations] --> E[Evidence importer]
    E --> D
    D --> F[Architecture-aware disassembly]
    D --> G[RTTI, layout, reflection analyzers]
    F --> H[Evidence, claims, proofs, conflicts]
    G --> H
    H --> V{Verification gate}
    V -->|verified| I[Verified C / C++ / Rust / docs]
    V -->|candidate| J[Opt-in candidate metadata]
    H --> S[Semantic projection and compiler roundtrip]
    S --> V
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
- Schema-v3 IR retains observations, claims, proof obligations, conflicts,
  capability outcomes, and a typed semantic projection independently.
- `verify` checks graph integrity and generic invariants; optional profiles add
  target-specific ground-truth checks.
- Emitters consume the IR and separate verified surfaces from experimental or
  metadata-only results.
- `refine --semantic` validates the exact input hash, projects class/union
  layouts, inheritance, vtable order, and enums, then compiles generated C++
  and Rust before writing the refined IR. It also emits a target-independent
  recovery plan that classifies every remaining semantic and ABI gap by the
  static, PDB, RTTI, call-site, or runtime evidence needed to resolve it.
- `score-semantic` compares verified facts with an exact-build owned oracle and
  fails below the requested precision threshold.
- `record-build` stores immutable snapshots and produces adjacent semantic
  JSON and Markdown diffs.
