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
DirectUI::ElementWithHWND`. The recovery plan names three evidence routes
for this (`pdb-base-record`, `rtti-base-descriptor`,
`constructor-vtable-chain`) -- two of the three are confirmed, verified
dead ends for this specific binary, not just "didn't fire this run":

- `rtti-base-descriptor`: dui70.dll has no RTTI at all. Confirmed with
  radare2's `avrr` (automatic RTTI vtable recovery), which found zero
  classes in the whole binary -- consistent with an older system DLL
  compiled with `/GR-`.
- `constructor-vtable-chain`: checked `HWNDElement`'s actual disassembly
  (RVA 0x7d180). It never calls `ElementWithHWND`'s constructor at all --
  the compiler fully inlined the base construction (set the vtable
  pointer directly, zeroed a handful of fields, `ret`, no `call`
  instruction anywhere in the ~0x30-byte function). The relationship is
  real in source but the literal call-chain evidence this route looks for
  was optimized away and does not exist in the compiled binary. Windissect
  correctly refuses to fabricate it.

So for binaries in this shape (no RTTI, base construction inlined --
plausibly common across older, aggressively-optimized system DLLs, not
just this one class), `constructor-vtable-chain` and `rtti-base-descriptor`
are structurally unusable and `pdb-base-record` is the only route left
standing, not just the first one worth trying.

Fix directions:
- Check whether windissect's PDB type parser (`pdbtype.rs`) already
  extracts `LF_CLASS`/base-class records from CodeView type info, and if
  so why that isn't wired into the base-relationship promotion path yet.
  PDB type records preserve source-level class hierarchy independent of
  what the optimizer did to the machine code, so this should work even
  when both other routes are dead.
- Once `pdb-base-record` works, consider detecting "no RTTI in this
  module" up front (one `avrr`-equivalent check) and skipping the RTTI
  route's recovery-plan gap entry entirely for such binaries, rather than
  listing it as an open evidence route that can never close.

### 3. A class's own vtable being 100% verified doesn't get its factory functions verified-callable

`InitProcessPriv`/`InitThread` (bare C exports, PDB-public-symbol-only,
no type info) and `Button::Create`/`TouchButton::Create`/etc. (real
`Class::Create(Element*, DWORD*, Element**)` static factories, PDB-certain
mangled signatures) never appear in the `claims` array at all -- not
"attempted and rejected," just never reached by the callable-proof pass.
This is true even for `Button::Create` specifically, whose target class
(`DirectUI::Button`) has a **fully verified** vtable (47/47 slots). A
class clearing 100% verified-slot status says nothing about whether the
free functions/static factories that construct it get proven callable;
those appear to be handled by an entirely separate pass that didn't run
on any of these five functions in this build.

Reproduced on `dui70.dll` (build F1920C0ED3DE254FE969E8E8CC4435CE-1):
searched the full `claims` array (19,137 entries) in
`recon-go/ir/dui70.pgressive.json/inventory.ir.json` for any claim
mentioning `InitProcessPriv`'s RVA (`0x81ff0`) or `Button::Create`'s
mangled name/RVA (`0x77c30`) -- zero matches for either. Both functions
were confirmed to actually work by manual, live, SEH-wrapped calls
outside windissect (see `venir-dui`'s `docs/dui-evidence.md`), not by
anything windissect itself proved.

Two different shapes of the same gap:
- `InitProcessPriv`/`InitThread` are bare C exports with no PDB type
  info at all (`sig.parse_ok: false`, `params: []`) -- their real
  argument shapes (5 args / 1 arg, both integer/pointer, confirmed by
  reading their own disassembly) aren't in any evidence windissect
  produces, static or dynamic. Nothing to promote to verified without
  new evidence-gathering (disassembly-derived argument recovery for
  PDB-public-only C exports), not a wiring bug.
- `Button::Create` has a full, real, structured C++ signature from the
  PDB (`?Create@Button@DirectUI@@SAJPEAVElement@2@PEAKPEAPEAV32@@Z`
  demangles cleanly) and its own target class is fully verified -- this
  one looks like it should be reachable by whatever pass proves
  `HWNDElement::Create`/`NativeHWNDHost`'s methods callable, but wasn't
  attempted at all for this build. Worth checking whether the
  callable-proof pass has its own separate target-selection logic that
  simply never queued this specific function, versus a real per-function
  failure that produced a conflict/rejected claim instead of an
  affirmative one (none of either was found -- it's absent, not
  rejected).

Fix directions:
- For the `Button::Create`-shaped case: instrument or trace why a
  function with a full structured signature and a fully-verified target
  class type doesn't get queued by the callable-proof pass, when
  `HWNDElement::Create` (structurally similar: a static factory taking
  an output pointer, real PDB signature) did get queued and proven for
  the same binary.
- For the `InitProcessPriv`-shaped case: this needs new evidence, not a
  wiring fix -- consider whether disassembly-derived argument-count/type
  inference (register/stack read patterns at function entry, already
  partially explored manually for both these functions) could feed a new
  evidence route for PDB-public-only C exports, similar in spirit to how
  `ProbeOperation::CallEnumProbe` (see "Fixed this session" below) added
  a new evidence route for enum values that plain PDB parsing couldn't
  supply.

## Fixed this session

- ~~Enum member values not recoverable when the PDB only carries a forward
  reference (no `LF_ENUMERATE` records survived)~~ -- added
  `ProbeOperation::CallEnumProbe` (construct a verified-layout object,
  call one verified vtable slot across a small candidate-value range,
  import every accepted value as a real proof-gated `EnumValue` claim).
  See `src/semantic_probe.rs`.
