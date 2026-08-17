# Windissect corpus and emitter pass — 2026-08-13

## Outcome

Windissect completed an exact-build compatibility corpus for the 43 Windows UI
targets in `venir/compat/windows-ui-binaries.json` and produced C, C++, and Rust
consumer surfaces on the system that supplied the binaries.

| Result | Count |
|---|---:|
| Corpus targets | 43 |
| Exact-build PDB verified | 42 |
| Verified static-only | 1 |
| Canonical IR files | 43 |
| Canonical IR logical size | 10.26 GiB |
| Generated header files | 28,779 |
| Generated header size | 325.89 MiB |
| Generated Rust crates | 43 |
| Generated Rust source/config files | 215 |
| Generated Rust size | 256.43 MiB |

The static-only target is the installed packaged Notepad executable. Its exact
PDB was unavailable from the configured symbol server and the executable has no
exports; the IR explicitly records that limitation instead of claiming PDB
coverage.

Machine-readable corpus results are stored in
`C:\Users\raze\reverse\windows\.venir-compat\compat-index.json`. The adjacent
`compat-report.md` contains the binary SHA-256 and PDB GUID+age for every target.

## Extraction performance

The extraction path now records phase timings. Compact mode retains canonical
facts and proof-relevant evidence while `pgressive` retains the complete raw
instruction, CFG, PDB, and layout observation inventory.

The largest measured target, `Windows.UI.Xaml.dll`, completed in 28.154 seconds:

| Phase | Seconds |
|---|---:|
| PE and PDB symbols | 1.144 |
| Demangling and signatures | 1.901 |
| PDB types | 2.978 |
| Disassembly and CFG | 5.322 |
| PE RTTI | 11.816 |
| Layout inference | 0.548 |
| Reflection | 0.035 |
| Serialization | 2.475 |

The resulting IR contains 346,255 symbols, 163,955 structured signatures,
12,015 PE vftables, and 31,864 additional PDB/type vtable records. All 14
generic verification checks passed.

## Scaling changes

- Normal compact extraction no longer retains verbose raw PDB record strings.
- Normal compact extraction discards raw instruction and CFG records after
  derived call, hash, RTTI, and layout facts are recorded.
- Layout recovery retains exhaustive observations only in `pgressive` mode.
- Factory/allocation layout proof no longer performs repeated global proof scans.
- Build history uses same-volume hard links for canonical IR snapshots and falls
  back to compact serialization when a link cannot be created.
- Header emission builds one symbol/class/type index per IR.
- C++ and Rust vcall emission build proof indexes once instead of rescanning all
  claims for every slot.
- Global C++ forward declarations are emitted once per binary rather than copied
  into every class header.

Control Center header generation fell from several minutes without completion
to 2.374 seconds. DWMCore fell from more than one minute to 2.536 seconds.
Deduplicating forward declarations reduced the full header corpus from 1.81 GiB
to 344.6 MiB at that stage; the final corpus is 325.89 MiB.

## Output boundary

Each header directory now has two explicit C++ surfaces:

- `<target>.h` is the compile-gated primary surface. It contains recovered ABI
  metadata plus proof-gated direct-call and virtual-call helpers.
- `<target>_candidates.h` is an opt-in exhaustive class-declaration umbrella.
  It preserves unresolved PDB-derived language and ownership information and is
  not labelled ABI-safe.

This prevents C++/CLI `$` identifiers, template ownership ambiguity,
class/namespace collisions, and malformed historical type spellings from
contaminating the verified consumer interface while keeping the evidence
available for refinement.

Class-header filenames are collision-safe on case-insensitive filesystems.
Case-folding collisions receive a deterministic qualified-name hash.

## Compilation and verification matrix

All commands used warning-as-error behavior.

| Gate | Result |
|---|---|
| Rust unit tests | 64 passed, 0 failed |
| Strict Rust clippy (`all-targets`, `all-features`, warnings + pedantic + nursery) | passed |
| Go tests | passed |
| Go vet | passed |
| C23 generated flat headers (`-Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow`) | 43/43 passed |
| C ABI headers under C++20 | 43/43 passed |
| Verified C++ primary headers under C++17 | 43/43 passed |
| Verified C++ primary headers under C++20 | 43/43 passed |
| Verified C++ primary headers under C++23 | 43/43 passed |
| Verified C++ primary headers under C++26 draft (`c++2c`) | 43/43 passed |
| Generated Rust crates | 43/43 generated |
| Generated Rust crates, MSVC `cargo check` | 43/43 passed |
| Venir strict C23 CMake build | passed |
| Venir CTest suite | 6/6 passed |

The Rust corpus generated in 79.10 seconds. A shared MSVC target directory was
used to check all 43 crates; the complete check took 204.96 seconds.

## Venir exact-build consumption

Venir now includes `venir_compat`, a strict C23 component backed by Windows
CNG (`bcrypt`) that computes a file SHA-256 and compares it to the build identity
recorded by Windissect. Its end-to-end test writes a known payload, validates the
known SHA-256, and rejects a mismatched identity.

This is the boundary Venir can apply before loading or calling generated private
interfaces. A timestamp or filename match alone is not accepted as exact-build
identity.

## Storage

Canonical and history IR files with byte-identical content were converted to
hard links only after SHA-256 equality checks. The logical archive structure is
unchanged. This recovered several GiB without deleting a canonical artifact or
build record.

At the end of the pass, drive C had approximately 14.87 GiB free.

## Current limitations

- The exhaustive candidate C++ umbrella is intentionally not guaranteed to
  compile. It is a refinement corpus, not a verified SDK.
- ARM64 and ARM64EC semantic recovery remain metadata-only.
- SYS static extraction is supported, but kernel runtime probing is withheld.
- The packaged Notepad specimen is static-only because its matching PDB was not
  available from the configured server.
- Exact field names inferred only from behavioral access patterns remain
  candidates until independent proof obligations are satisfied.

## Resume point

The next productive pass should consume candidate-header compiler diagnostics
as structured refinement jobs, prove or rewrite each declaration from the IR
type graph, and promote only classes whose ownership, layout, signature, and
language obligations all pass. The verified primary surface and the 43-target
corpus provide a stable baseline for that work.
