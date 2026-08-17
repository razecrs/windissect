# Windissect parity and generalization plan

## Objective

Windissect must reproduce or exceed ExplorerPatcher’s practical DUI70 interface coverage through an automated, evidence-preserving pipeline, while also working on unrelated DLL, EXE, and SYS targets. ExplorerPatcher declarations may identify discrepancies, but they are never accepted as proof.

## Non-negotiable success gates

1. **Corpus parity:** Windissect matches or exceeds EP’s declaration count on the same target/build.
2. **Independent proof:** every promoted callable/layout fact has PE/PDB, disassembly, RTTI, runtime, or explicit exact-build evidence.
3. **Class parity:** representative classes match or exceed EP in methods, inheritance, vtables, fields, enums, and properties where evidence exists.
4. **ABI quality:** signatures, calling conventions, constness, field offsets, and vtable slots are validated or explicitly marked uncertain.
5. **Output usability:** generated C/C++ and Rust compile in supported toolchains; unsupported facts are not emitted as trustworthy calls.
6. **Genericity:** no DirectUI-specific recovery rule is required for the same capability on another target.
7. **Regression:** all parity fixtures, non-DUI fixtures, and negative/stripped-PDB cases remain passing.

## Phase 1 — Measurement and benchmark control

- Freeze exact PE/PDB identities for DUI70 and each comparison target.
- Normalize EP and Windissect declarations into method/class/type records.
- Store intersection, Windissect-only, EP-only, signature conflicts, and class metadata as JSON/CSV.
- Maintain a gold fixture with known layouts, vtables, locals, inline sites, and source mappings.
- Track runtime, memory, generated-file counts, compile success, precision, recall, and false-positive rates.

## Phase 2 — Exhaustive PDB acquisition

Implement `pgressive` as a loss-preserving reader of every available stream:

- DBI modules, section contributions, publics, globals, and hashes;
- procedures, thunks, blocks, locals, register/stack locations, inline sites, annotations;
- TPI/IPI type graphs, forward references, field lists, bitfields, templates, type servers;
- source files, checksums, lines, inlinee lines, OMAP, FPO/unwind, exception scopes;
- build/linker records, Edit-and-Continue, PGO/instrumentation, resources, TLS, CLR, and incremental-link records.

Every raw record is retained before typed projection. Unsupported records remain visible with a status rather than being dropped.

## Phase 3 — Independent semantic recovery

For each candidate declaration or layout:

1. Locate matching PDB type/procedure records.
2. Locate PE bytes and section-backed RVA.
3. Decode relevant instructions with architecture-specific metadata.
4. Confirm field offsets through repeated member-access observations.
5. Confirm vtables through RTTI, vftable symbols, and executable target pointers.
6. Confirm inheritance through PDB bases, RTTI, constructor/destructor adjustments, and vtable layout.
7. Confirm signatures through PDB type indices, call sites, ABI rules, and compiler fixture behavior.
8. Record conflicting evidence instead of silently choosing one answer.

## Phase 4 — Refine engine

`refine` converts discrepancies into independent recovery jobs:

- missing class or method;
- missing inline/pure-virtual/special member;
- signature disagreement;
- missing base/vtable/field/enum/property;
- alias or mangling mismatch;
- build-specific variation.

Each job receives evidence requirements and a state: unresolved, candidate, verified, or withheld. Reference corpora trigger jobs but cannot close them.

Implemented foundation: schema-v3 IR persists these typed jobs, verifier checks
their references and proof gate, and exact-build PDB function records can close
callable/signature requirements only when the function name demangles into a
structured ABI and static analysis decoded its PE body. Missing layouts,
virtual slots, fields, enums, and unresolved symbols remain open work rather
than being promoted from the comparison corpus.

## Phase 5 — Generic automation

Implement recovery as target-neutral rules over PE/PDB/IR primitives:

- PDB type-index closure;
- procedure/thunk graph construction;
- constructor/destructor and this-adjustment analysis;
- vtable and RTTI scanning;
- member-access data-flow analysis;
- enum/alias/template normalization;
- call-site and ABI inference;
- build-to-build symbol and semantic matching.

DirectUI-specific knowledge may be stored as optional evidence packs or profiles, never embedded as the only implementation path.

## Phase 6 — Output and verification

- Emit separate verified and candidate C/C++/Rust surfaces.
- Add compile tests for C17/C20/C23/C26-compatible modes and C++17/20/23/26 modes where toolchains support them.
- Validate field offsets, object sizes, vtable slots, enum values, and calling conventions.
- Add safe runtime probes for exact-build targets.
- Reject or quarantine unsupported ABI declarations.

## Phase 7 — Parity scoreboard

The scoreboard must report, per target and class:

- total declarations;
- independently verified declarations;
- candidate declarations;
- EP-only, Windissect-only, and common methods;
- signature conflicts;
- fields, bases, vtables, enums, properties;
- proof coverage;
- compile/runtime results;
- generation time and output size.

No “win” is declared until Windissect reaches EP parity on DUI70 and demonstrates the same automated capabilities on at least one unrelated DLL and one SYS target.

## Operating principle

The strategy is: **observe everything, compare everything, prove independently, automate the proven method, and measure again**. The goal is not a larger guessed header; it is a reproducible system that can reach handwritten-quality coverage without being handwritten for one DLL.
