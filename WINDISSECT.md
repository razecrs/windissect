# Windissect

Windissect is a target-independent Windows binary dissection and interface-reconstruction tool. It accepts a PE image—DLL, EXE, or SYS—and, when available, its matching Microsoft PDB. It converts the binary and debugging information into an identity-anchored intermediate representation (IR), preserves evidence and uncertainty, and emits inspectable C, C++, Rust, assembly, documentation, and build-to-build differences.

The project is not a DirectUI-only parser and it is not a claim that every declaration recovered from a binary is automatically correct. DUI70 is the deep demonstration case; the extraction model is intended to work on arbitrary Windows PE targets.

## The problem it solves

Windows private binaries often expose useful implementation details only through a combination of:

- PE exports, sections, relocations, imports, resources, and exception data;
- PDB public and private symbols;
- CodeView type records and type-index graphs;
- compiler-generated names, thunks, RTTI, and vtables;
- machine-code instruction patterns and data-flow observations;
- reflection/property metadata;
- exact-build identity and manually verified observations.

Those sources are incomplete and sometimes contradictory. A useful reconstruction tool must therefore preserve both the recovered interface and the reason it believes each fact.

## Core design

Windissect uses a staged pipeline:

1. **PE identity and structure** — parse machine type, image base, timestamp, sections, exports, imports, relocations, CodeView GUID/age, and SHA-256.
2. **PDB extraction** — validate the PDB against the PE and collect public symbols, module procedures, private functions, thunks, data/TLS symbols, constants, build records, and available type information.
3. **Demangling and classification** — recover namespaces, classes, methods, constructors, destructors, operators, C functions, data, thunks, aliases, and library/boilerplate status.
4. **Static enrichment** — map symbols to file-backed bytes, determine function sizes, decode instructions with architecture-aware rules, compute body hashes, derive call relationships, and record imports.
5. **RTTI/vtable recovery** — inspect MSVC RTTI and vftable structures where present, retaining the observations and their confidence.
6. **Layout and reflection analysis** — record direct member-access observations, PDB-derived types, property systems, aliases, and other metadata.
7. **Evidence graph** — represent evidence, claims, proofs, conflicts, provenance, and usability status in the IR.
8. **Semantic projection** — produce separate verified and candidate class/layout/enum models. Candidate information never becomes proof merely because it is plausible or appears in an external reference corpus.
9. **Emission and validation** — generate C/C++, Rust, symbols, assembly, documentation, evidence reports, and compiler/structural checks.
10. **History and diffs** — archive exact-build IR snapshots and produce semantic changes between Windows builds.

## Evidence model

Every important fact is intended to carry:

- a stable claim identifier;
- one or more evidence records;
- the source tool or method;
- target identity and location where applicable;
- a proof or validation result;
- provenance and confidence;
- a status such as verified, metadata-only/candidate, or withheld;
- conflict information when competing observations disagree.

Verified output is reserved for facts that satisfy the project’s proof requirements. PDB-derived metadata can be highly useful while still remaining a candidate when the binary does not independently support it. Manual exact-build evidence can promote a fact when its PE identity, location, and scope are validated.

## `pgressive`

`pgressive` is Windissect’s exhaustive PE/PDB inventory mode. The name is intentional: it means aggressive traversal of available information, not automatic promotion of every observation.

Example:

```powershell
windissect extract target.dll --pdb target.pdb --pgressive --out inventory
```

The mode runs the normal extraction pipeline and writes:

- `inventory.ir.json` — the complete Windissect IR snapshot;
- `inventory.json` — a machine-readable coverage inventory;
- counts for symbols, functions, exports, claims, evidence, calls, vtables, types, and reflection data;
- PDB stream coverage for procedures, thunks, locals/register records, blocks, inline sites, data/TLS symbols, constants, build information, and annotations;
- explicit status for categories that are unavailable, partial, or not yet modeled.

The intended long-term `pgressive` surface includes, when the PDB contains them:

- local variables and names;
- lexical scopes and block nesting;
- register and stack locations;
- inline sites and inline call trees;
- source/line and caller-callee mappings;
- call-site parameter annotations;
- compiler-generated names, closures, lambdas, and templates;
- type-server references and imported type graphs;
- forward declarations, bitfields, packing, inheritance, and virtual-function shapes;
- static and TLS symbols;
- section contributions and module ownership;
- source checksums, paths, embedded/source-server metadata;
- Edit-and-Continue, FPO/unwind, exception scopes, OMAP, linker/DIA, PGO, CodeView annotations, resources, CLR/mixed-mode, and incremental-link records;
- GUID, age, signature, compiler, linker, and build identity metadata.

The inventory distinguishes “the PDB contains evidence of this category” from “Windissect has fully serialized and verified every record in this category.”

## `refine`

`refine` is an evidence-gated discrepancy and recovery mode. It compares the current IR with optional reference declarations or recovered observations and produces actionable differences:

- common methods and signature conflicts;
- reference-only declarations;
- known-class methods missing from the IR;
- stubs, inline methods, pure virtuals, special members, and unknown classes;
- generic recoveries from independent rules;
- semantic class/layout/enum projections;
- optional manual-layout, runtime-probe, or oracle evidence imports.

Every imported discrepancy is also persisted as a typed recovery job with an
unresolved, candidate, verified, or withheld state. Jobs record the matched IR
symbols and the evidence still required for symbol identity, ABI, executable
mapping, call-site/type corroboration, and virtual slots. An identity-matched
PDB function can close a callable job only when its MSVC name produces a
structured signature and its RVA has a decoded body from the exact PE build.

Reference projects such as ExplorerPatcher are comparison material only. Their declarations remain non-callable candidates and discrepancy triggers. They are not training data and cannot independently promote a Windissect claim.

## Outputs

Windissect can emit:

- C++ headers for recovered classes and semantic layouts;
- C-facing symbol tables with RVAs and link metadata;
- Rust FFI/semantic crates;
- annotated assembly;
- API and codebase markdown documentation;
- strict evidence-only output;
- machine-readable IR and semantic JSON;
- build archives and semantic diffs.

Generated callable declarations are subject to the project’s proof/status policy. Unknown or unsupported ABI details should remain opaque or candidate rather than looking like trustworthy callable interfaces.

## Build identity and history

The PE and PDB are treated as a pair. Windissect records:

- PE SHA-256;
- machine and image base;
- timestamp and section information;
- CodeView GUID and age;
- PDB identity and symbol source;
- generated IR schema and tool version.

Build snapshots can be archived and compared so changes in symbols, methods, classes, fields, vtables, enums, exports, hashes, and evidence are visible across Windows versions.

## Current demonstrated behavior

A generated clang-cl debug fixture containing inheritance, virtual methods, an inline method, a constructor, locals, and an exported function was processed end-to-end. The resulting PDB/PE run produced thousands of symbols, private procedures, thunks, local/register records, inline-site records, static/TLS records, build metadata, vtable observations, claims, and evidence. The Rust test suite and clippy checks pass for the current source tree.

DUI70 remains the deep case because it exercises a large private C++ surface and exact-build evidence workflow. The architecture itself is not specialized to DUI70.

## What a PDB cannot guarantee

A PDB does not necessarily contain all information about a program. Optimized or public-only builds may omit locals, private procedures, complete layouts, source paths, inline details, or type records. A PDB also does not contain the executable’s complete behavior or replace disassembly of the PE image. Windissect therefore reports unavailable and partial categories explicitly and combines PDB data with binary evidence.

## Current limitations

The most important remaining work is full-fidelity serialization and proof for every available PDB stream, especially local locations, lexical nesting, inline annotation graphs, source/checksum records, call-site annotations, OMAP, exception scopes, type servers, Edit-and-Continue, PGO/instrumentation, CLR metadata, and incremental-link records. Automatic recovery of complete private C++ layouts and ABI-safe Rust wrappers still requires independent binary/runtime evidence beyond names alone.

## Guiding rule

Windissect’s goal is not to print the largest possible header. Its goal is to preserve everything recoverable, identify what is missing, show where every fact came from, and emit only the level of interface that the evidence justifies.
