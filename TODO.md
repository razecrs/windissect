# Windissect TODO

Real gaps found while using windissect against live targets, not
speculative wishlist items. Each entry names the exact reproduction.

## Open

### 1. Automatic runtime probing crashes on DLLs that aren't standalone-loadable

`semantic_probe::automatic_manifest` blindly selects up to 32
verified-callable zero-argument functions and calls them cold, with no
COM/XAML apartment or host-process context initialized. This is correct
for a target designed to be called standalone, but many real targets
(e.g. `twinui.pcshell.dll`) are never meant to run outside their real host
process (`explorer.exe`/`dwm.exe`) and access-violate immediately when
called this way.

Reproduced: `refine --semantic` against `twinui.pcshell.dll` (build
478851127-FCFCF4EFC4BB468AC3C12242EB80463A-1) crashed the probe helper
with exit code `0xc0000005`, aborting the entire refine run rather than
just failing the probe step. The isolated child process
(`semantic_probe::run_isolated`) contained the crash to itself, correctly
not taking down the parent -- but a probe failure currently aborts the
whole `refine --semantic` pipeline instead of degrading to static-only
results and continuing.

Fix directions:
- Make a probe crash non-fatal to the overall refine run: fall back to
  `write_static_only` and continue, the same as the "no automatic manifest
  available" path already does.
- Consider a target classification (standalone-safe vs. host-only) so
  `automatic_manifest` skips blind calls entirely on DLLs known to require
  host-process context, rather than relying on the isolated-crash
  containment as the only safety net.

### 2. Verified vtables don't imply a verified base-class relationship

A class's own vtable(s) can clear 100% verified-slot status while its
inheritance relationship to a base class stays unverified indefinitely --
which keeps the whole class at `candidate`, even when every method it
actually implements is independently proven callable.

Reproduced on `dui70.dll` (build
F1920C0ED3DE254FE969E8E8CC4435CE-1): `DirectUI::HWNDElement` has all 3 of
its own vtables fully verified (every slot proven), but stays `candidate`
solely because `HWNDElement -> DirectUI::ElementWithHWND` has
`relationship_verified: false`. Same pattern on `DirectUI::HWNDHost ->
DirectUI::ElementWithHWND`. The recovery plan already names the right
evidence routes for this (`pdb-base-record`, `rtti-base-descriptor`,
`constructor-vtable-chain`) but none fired for either relationship in this
build.

Fix directions:
- Check why RTTI base-descriptor recovery isn't closing this specific,
  common shape of gap (a verified-vtable class with only its own-base
  relationship unresolved) -- worth checking whether dui70.dll's RTTI
  `BaseClassArray` for these vtables is present but unparsed, or genuinely
  absent (compiled without full RTTI base info) and needs the
  constructor-vtable-chain route instead.
- This exact pattern (own vtables 100% verified, one unverified base
  relationship) is common enough across dui70's class hierarchy that it's
  worth a dedicated recovery pass rather than only the general
  `constructor-to-destructor-edge` corroboration path.

## Fixed this session

- ~~Enum member values not recoverable when the PDB only carries a forward
  reference (no `LF_ENUMERATE` records survived)~~ -- added
  `ProbeOperation::CallEnumProbe` (construct a verified-layout object,
  call one verified vtable slot across a small candidate-value range,
  import every accepted value as a real proof-gated `EnumValue` claim).
  See `src/semantic_probe.rs`.
