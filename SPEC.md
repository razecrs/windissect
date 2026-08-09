# Windissect architecture

Windissect is a target-independent Windows binary dissection pipeline. A target
is a PE image (`.dll`, `.exe`, or `.sys`) plus an optional, identity-matched PDB.

## Pipeline

1. `extract.rs` reads PE identity, exports, ordinals, forwarders, architecture,
   image base, and CodeView GUID/age.
2. `pdbsym.rs` validates PDB identity and collects global publics plus private
   procedures from module streams, preserving aliases and procedure lengths.
3. `demangle.rs` and `typeparse.rs` turn MSVC names into structured signatures
   while retaining unparsed source text.
4. `enrich.rs` uses architecture-appropriate disassembly to calculate safe
   function ranges, hashes, direct-call edges, imports, and jump thunks.
5. `model.rs` serializes the version-anchored IR. Emitters consume only this IR.
6. Emitters produce C++, Rust, C23 symbol tables, and Markdown documentation.
7. `cmd/windissect` orchestrates a curated fleet, exact symbol-server downloads,
   GUID+age caching, and batch generation.
8. `diff.rs` compares stable symbol identities across IRs and emits JSON plus
   Markdown change reports. `history.rs` stores immutable per-build snapshots,
   an ordered target index, and adjacent-build diffs suitable for static sites.

## Trust rules

- Never merge a PDB whose GUID/age does not match the PE CodeView record.
- Never decode an unsupported architecture as another instruction set.
- Forwarded exports and data are not disassembled as functions.
- Unknown types and signatures remain explicit raw/unknown values.
- Target-specific validation belongs in an optional profile; structural IR
  validation remains generic.
- Generated runtime addresses are RVAs relative to the IR's recorded image base.

## Current target profiles

DUI70 supplies the mature DirectUI categorization, reflection recovery, golden
checks, and documentation corpus. Those are a specialization layered on the
generic Windissect core, not the boundary of the project.
