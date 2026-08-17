# DUI70 1v1 raw results

## Inputs

| Input | Value |
|---|---|
| Windissect IR | `target/dui70-refined.json` (latest exact-build regeneration) |
| DUI70 DLL SHA-256 | `2878ECCC8351F19888DE58271684332F65BC103FC67664436F3DC26C30E16A5F` |
| PDB GUID+age | `1F9481899ABD1A4D518D17695D847D90+1` |
| ExplorerPatcher checkout | `../prior-art/explorerpatcher-dui70` |
| ExplorerPatcher branch | `main` |
| ExplorerPatcher commit | `047c13d3f94e924033fcf6b884beb23149da4284` |
| Comparison JSON | `target/ep-semantic-refine-report.json` |
| Semantic JSON | `target/dui70-semantic-current/semantic.json` |

## Declaration surface

| Metric | Windissect | ExplorerPatcher |
|---|---:|---:|
| Classes | 766 | 350 |
| Declarations | 7,532 | 4,095 |
| Common classes | 214 | 214 |
| Common methods | 3,415 | 3,415 |
| Windissect-only method keys | 3,738 | 0 |
| EP-only declarations | 440 | 440 |
| Implementation-backed EP-only declarations | 0 | 0 |
| Declaration-only EP-only declarations | 116 | 116 |
| Stub EP-only declarations | 26 | 26 |
| Inline EP-only declarations | 227 | 227 |
| Pure-virtual EP-only declarations | 40 | 40 |
| Special-member EP-only declarations | 31 | 31 |
| Signature conflicts | 3 | 3 |

## Reference declaration classification

| ExplorerPatcher declaration kind | Count |
|---|---:|
| Implementation-backed | 365 |
| Declaration-only | 472 |
| Stub-backed | 2,805 |
| Inline | 271 |
| Pure virtual | 40 |
| Special member | 142 |

## Independent recovery jobs

| State | Count |
|---|---:|
| Total | 4,095 |
| Verified | 1,913 |
| Candidate | 1,750 |
| Unresolved | 432 |
| Withheld | 0 |

## Semantic surface

| Metric | Windissect | ExplorerPatcher source-tree lexical result |
|---|---:|---:|
| Verified complete classes | 129 | — |
| Candidate/withheld classes | 507 | — |
| Verified named fields | 91 | — |
| Verified packed bitfields with exact bit positions | 26 | — |
| Verified unnamed object-storage facts | 984 | — |
| Verified field/storage facts, total | 1,075 | — |
| Underscore-prefixed field declaration lines | — | 621 |
| Verified base relationships | 293 | — |
| Explicit inheritance declaration lines | — | 122 |
| Verified vtables | 440 | — |
| Verified vtable slots | 8,370 | — |
| Explicit `vtable`/`vftable` source lines | — | 0 |
| Verified enums with values | 0 | — |
| Candidate enum types discovered in signatures | 87 | — |
| Enum declaration lines | — | 64 |

## Representative method sets

| Class | Windissect | ExplorerPatcher | Common | EP-only | Windissect-only |
|---|---:|---:|---:|---:|---:|
| `DirectUI::Button` | 23 | 21 | 21 | 0 | 2 |
| `DirectUI::DUIXmlParser` | 137 | 138 | 134 | 4 | 3 |
| `DirectUI::Element` | 397 | 394 | 393 | 1 | 4 |
| `DirectUI::EventManager` | 40 | 39 | 39 | 0 | 1 |
| `DirectUI::HWNDElement` | 64 | 62 | 62 | 0 | 2 |
| `DirectUI::RichText` | 89 | 107 | 88 | 19 | 1 |
| `DirectUI::TouchScrollViewer` | 187 | 201 | 185 | 16 | 2 |
| `DirectUI::Value` | 93 | 93 | 92 | 1 | 1 |

## Representative exact-build semantic facts

| Class | Complete status | Size | Verified named fields | Verified storage facts | Verified bases | Verified vtables | Verified slots |
|---|---|---:|---:|---:|---:|---:|---:|
| `DirectUI::Button` | candidate | 208 | 0 | 0 | 1 | 1 | 47 |
| `DirectUI::DUIXmlParser` | candidate | — | 7 | 29 | 0 | 1 | 1 |
| `DirectUI::Element` | verified | 200 | 31 | 28 | 0 | 5 | 238 |
| `DirectUI::HWNDElement` | candidate | 256 | 4 | 9 | 0 | 3 | 180 |
| `DirectUI::RichText` | candidate | — | 3 | 20 | 0 | 0 | 0 |
| `DirectUI::TouchScrollViewer` | candidate | — | 7 | 67 | 0 | 0 | 0 |
| `DirectUI::Value` | candidate | — | 0 | 10 | 0 | 0 | 0 |

## Files and source size

| Metric | Windissect | ExplorerPatcher |
|---|---:|---:|
| Tool/source files (`.rs`/`.go` vs `.h`/`.hpp`/`.c`/`.cpp`) | 32 | 162 |
| Tool/source LOC | 17,090 | 17,115 |
| Generated/reconstructed headers | 396 | 159 |
| Generated/reconstructed documentation files | 393 | 90 |
| Rust source support | yes | no |
| Rust files in reference checkout | — | 0 |

## Timing

| Operation | Elapsed |
|---|---:|
| Exact DLL+PDB extraction | 2.262 s |
| Semantic refine and comparison | 14.321 s |
| Header emission, 396 files | 30.935 s |

## Verification results

| Check | Result |
|---|---|
| Generic IR verification | 14/14 passed |
| DUI70 ground-truth profile | 19/19 passed |
| Individual generated C++17 headers | 395/395 passed |
| Master C++ standards | C++17, C++20, C++23, C++26-draft passed |
| C standards | C17, C23, C26-draft passed |
| C++ calls/vcalls with `-Wall -Wextra -Werror` | passed |
| Generated Rust FFI crate with `-D warnings` | passed |
| Verified semantic C++ surface | passed |
| Candidate semantic C++ surface | passed |
| Verified semantic Rust crate with `-D warnings` | passed |
| Strict project Clippy | passed |
| Unit tests | 63/63 passed |
