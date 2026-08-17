# Windissect

Windissect turns Windows PE binaries and their matching Microsoft PDBs into a
version-anchored, machine-readable map of Windows internals. Its extraction
model is target-agnostic: DUI70 is the deep validation corpus, while AMSI
exercises the generic PE/export path. The fleet orchestrator includes curated
targets across DWM, composition, shell, taskbar, XAML, input, and storage.

## What it produces

- typed JSON IR for exports and private PDB procedures
- MSVC-demangled signatures with structured C++ types
- function sizes, implementation hashes, call edges, and imported APIs
- generated C++ declarations and proof-gated Rust FFI crates
- exact-build C++ RVA helpers and virtual-slot helpers when callable identity
  and ABI claims are independently proven
- C23 RVA symbol tables for runtime consumers
- generated API documentation carrying evidence and usability status

See the [architecture](docs/architecture.md), the
[five-minute demonstration](docs/five-minute-demo.md), and the explicit
[verified versus experimental output policy](docs/output-status.md).

Generated native artifacts have an explicit language floor and are continuously
compiled in every newer standards mode: C17, C23, C26 draft (`-std=c2y`), and
C++17, C++20, C++23, C++26 draft (`-std=c++2c`). The emitters avoid relying on
newer-dialect-only syntax unless the generated header advertises that minimum.
Windissect also names its C-shaped ABI surface consumed from C++20 through
`extern "C"` the **C20 profile**. This is a Windissect compatibility profile,
not a claim that ISO published a C20 language standard.

Every IR records the exact binary, image base, architecture, timestamp, and PDB
GUID/age. Windissect rejects mismatched PDBs. Metadata extraction may remain
available for an unsupported instruction set, but disassembly-dependent
analysis is withheld rather than decoded as the wrong architecture.

For x64 targets, `windissect_calls.h` exposes typed calls only when both
addressability and signature claims pass their proof obligations. Its default
Windows resolver checks the loaded image's PE timestamp and bounds.
`windissect_vcalls.h` applies the same proof boundary to virtual slots;
conflicting or incomplete signatures remain metadata-only.

## Analyze one binary

```powershell
cargo build --release
target\release\windissect extract C:\Windows\System32\dwmapi.dll --out ir\dwmapi.json
target\release\windissect extract C:\Windows\System32\dwmapi.dll --pdb probe\dwmapi.pdb --out ir\dwmapi.json
target\release\windissect verify --ir ir\dwmapi.json
target\release\windissect emit-headers --ir ir\dwmapi.json --out headers\dwmapi
target\release\windissect emit-rust --ir ir\dwmapi.json --out rust\dwmapi-sys
target\release\windissect emit-syms --ir ir\dwmapi.json --out syms
target\release\windissect diff ir\old\dwmapi.json ir\new\dwmapi.json --json-out changes.json --markdown-out changes.md
target\release\windissect record-build ir\dwmapi.json --history history
target\release\windissect refine --semantic --ir ir\dwmapi.json --binary C:\Windows\System32\dwmapi.dll --out refinement\dwmapi.json --out-ir ir\dwmapi.semantic.json --semantic-out semantic\dwmapi
target\release\windissect refine --ir ir\dwmapi.json --reference path\to\headers --out refinement\dwmapi-reference.json --out-ir ir\dwmapi.refined.json
```

`emit-headers` writes a compile-gated primary `<target>.h` containing verified
ABI metadata and proof-gated call helpers. Exhaustive reconstructed class
declarations are kept in `<target>_candidates.h`; that opt-in umbrella may
contain unresolved language or ownership ambiguities and is not presented as
an ABI-safe SDK.

Reference-guided refinement writes a proof-gated recovery queue into the
refined IR. A reference declaration can open a job, but only independently
recorded PE/PDB/disassembly evidence can move that job to `verified`.
Semantic refinement also writes `recovery-plan.json` and `recovery-plan.md`.
This target-independent queue is derived only from the IR and ranks unresolved
ABI, layout, inheritance, vtable, enum, and proof-conflict facts by the next
independent evidence route; it does not require a reference project.

For the quickest reproducible run on a fresh Windows clone:

```powershell
pwsh -File scripts/demo.ps1
```

This analyzes the installed `amsi.dll`, verifies the resulting schema-v3 IR,
and emits C, C++, Rust, symbol, and evidence surfaces under `target/demo/`.

## Build history and diffs

Fleet extraction automatically records every successfully analyzed build. The
archive is intentionally static-host friendly:

```text
history/index.json
history/<target>/index.json
history/<target>/builds/<timestamp-guid-age>/ir.json
history/<target>/changes/<old-key>__<new-key>.json
history/<target>/changes/<old-key>__<new-key>.md
```

The root `index.json` catalogs every target and links to its target index. Each
target `index.json` lists builds in observation order,
the latest build, links to each immutable IR and adjacent diff, and embeds a
change summary. Diff JSON separates additions/removals from signature,
implementation, call-graph, import, size, kind, export-status, and RVA changes.
RVA movement is recorded independently so consumers can distinguish address
churn from behavioral changes.

## Analyze the Windows internals fleet

The Go orchestrator finds the curated System32 targets, performs a metadata-only
pass, downloads the exact PDB from Microsoft's symbol server into a GUID+age
cache, repeats extraction with symbols, and emits per-target headers.

```powershell
go build -o bin\windissect-fleet.exe .\cmd\windissect
bin\windissect-fleet.exe --extractor target\release\windissect.exe pull
bin\windissect-fleet.exe --extractor target\release\windissect.exe emit
```

Microsoft binaries and PDBs are not distributed by this repository.

## Status

Version 0.1.0 includes the generic PE/PDB IR, multi-target fleet, PE-native
RTTI/vftable recovery, proof-gated MSVC x64 semantic layouts, separate
verified/candidate C++ and Rust output, conservative layout observations,
evidence/proof graph, and per-build semantic diffing.
DUI70 is the deep validation corpus; AMSI is the small unrelated reproducible
case. Layout claims without certified proof remain experimental and are not
promoted into callable declarations. Release evidence and artifact hashes are
recorded in [RELEASE.md](RELEASE.md).

The included x64 member-access evidence pack is deliberately marked `draft`;
its observations remain metadata-only until the documented cross-binary corpus
gate is satisfied.

The owned semantic fixture measures exact-build class, union, bitfield,
inheritance, vtable, and enum facts with `score-semantic`; its current oracle
requires at least 99.9% precision. Typedef aliases are withheld because the
current PDB parser does not expose CodeView `LF_ALIAS` records. Runtime probing
is opt-in, isolated, exact-build checked, and DLL-only. SYS analysis remains
static.

Generated trees, downloaded Microsoft binaries/PDBs, IDA databases, and the
143.2 MiB canonical DUI70 IR are deliberately excluded from Git. This avoids
mixing stale outputs with source. The verified local artifact and its expected
release-asset hash are documented in `RELEASE.md`.

## License

MIT
