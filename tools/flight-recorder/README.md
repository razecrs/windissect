# Windissect Flight Recorder

A small Windows-only desktop flight recorder. Windissect-generated bindings
for the exact installed `dxgi`, `d3d11`, `mfplat`, and `mfreadwrite` builds are
the primary ABI provenance. Raw `windows-sys` calls fill only public Windows SDK
surface gaps that stripped public PDBs could not recover.

Defaults target a mostly-static 1920×1080 desktop: 40 kbit/s, at most 10 changed
frames per second, 60-second crash-loss segments, and a strict 500 MiB rolling
directory.

```powershell
cargo build --release --manifest-path tools\flight-recorder\Cargo.toml
tools\flight-recorder\target\release\windissect-flight-recorder.exe `
  --output D:\Recordings --gpu igpu
```

The bitrate is intentionally severe. High-motion content will either lose
quality or consume the rolling window faster; the disk ceiling always wins.
