# Releases

What each release was verified against before it shipped, newest first. The
user-facing notes are on the
[releases page](https://github.com/razecrs/windissect/releases).

## v1.0.1

Tagged commit `63a934bf`. Fixes the two bugs reported after launch (a matching
local PDB was downloaded again; `windissect` with no arguments failed on an
installed copy) and adds Linux builds.

### Verified release gates

- CI on the tagged commit, Linux job: `cargo build`, `cargo fmt --check`,
  `cargo test` (109 passed), `cargo clippy --all-targets --all-features` with
  `-D warnings -W clippy::pedantic -W clippy::nursery`, `go test ./...`,
  `go vet ./...`
- CI on the tagged commit, Windows job: AMSI analyze and verify demo, and the
  generated C, C++ and Rust outputs compile
- Linux release build on Ubuntu 22.04: static CLI, fleet, desktop app and
  terminal UI; the desktop app needs glibc 2.35 or newer
- Local PDB fix: identity read correctly from 8 cached Microsoft PDBs,
  including DUI70, whose PDB information-stream age differs from its DBI age;
  a PDB next to the binary is used with an empty cache and verifies 14/14; a
  PDB for another build is ignored and the right one downloaded
- Windows zip: `windissect --version` reports 1.0.1, and `windissect` with no
  arguments starts the bundled terminal UI from outside a source checkout
- Linux tarball: checksums verify, `install.sh` installs per user,
  `windissect --version` reports 1.0.1, and the terminal UI starts
- Linux pipeline on `cfgbkend.dll`: PDB download, extraction and verify 14/14,
  the same result as on Windows

### Checksums (SHA-256)

```
22a0b12d839dd54cb975ead11cc791d6e80b2d769a630a17da8fb1c43b40255d  Windissect-v1.0.1-setup-x64.exe
d332075e64321f6b50d759b61a9c3640377d1eaa1f308b6654806e315ff7fb59  Windissect-v1.0.1-windows-x64.zip
584baeef7373a5fe63915699b4c284448b187323ef8426178734792d741d517c  Windissect-v1.0.1-linux-x64.tar.gz
```

## v1.0.0

Tagged commit `54dc70c7`. The first release with the desktop app and a Windows
installer.

### Verified release gates

- CI on the tagged commit: both jobs green, with the same steps as above
- Installer: installs per user, `windissect --version` reports 1.0.0, and it
  uninstalls cleanly

### Checksums (SHA-256)

```
0a24afbed0fbc3e7147946c7246e40057fb74c9f2d8b9122ede47e29404e87eb  Windissect-v1.0.0-setup-x64.exe
dc72b38596af4638f5dc6ca8186e63f521bd0b1775de2cb11356405d86936f16  Windissect-v1.0.0-windows-x64.zip
```

## v0.1.0

### Verified release gates

- schema-v2 generic and DUI70 profile verification: 18/18
- proof graph: 2,690 evidence records, 2,690 claims, 2,345 proofs,
  39 retained conflicts, and no duplicate or dangling IDs
- Rust tests: 21 passed
- `cargo clippy --all-targets -- -D warnings`: passed
- Go orchestration tests and `go vet ./...`: passed
- 395 generated DUI70 C++ headers compile as C++17
- aggregate output compiles as C17, C23, C26 draft, C++17, C++20, C++23,
  C++26 draft, and the Windissect C20 bridge
- generated DUI70 Rust crate passes `cargo check --offline`
- unrelated AMSI export-only outputs compile in the same suite

### Canonical deep-case artifact

The canonical `ir/dui70.json` is a 143.2 MiB build-anchored schema-v2 corpus
designed for distribution separately from the source repository. The verified
local artifact has SHA-256:

`700E80F5145404C1D6325E071869E3F7FD328420796FB38ADDABF14E418F209F`

Exact input identities:

- `dui70.dll`: `2878ECCC8351F19888DE58271684332F65BC103FC67664436F3DC26C30E16A5F`
- `DUI70.pdb`: `6AEA78E85D4286110DCB4FF1C6B360B196BB3AB82C5E0D9B40CFACBA3EF67091`
- PDB GUID+age: `1F9481899ABD1A4D518D17695D847D90+1`

## Artifact policy

Generated headers, Rust crates, documentation, analysis databases, downloaded
PDBs, and build history are reproducible working outputs and are excluded from
source control. The DUI70 corpus can be published as a release artifact, while
other targets can be reconstructed from locally supplied Windows binaries and
identity-matched PDBs. Manually established evidence under
`analysis/manual-layouts/` and the evidence-pack definitions are maintained as
versioned source material. The included x64 member-access evidence pack remains
draft and does not authorize callable output.
