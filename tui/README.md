# Windissect TUI

Interactive Ink frontend for the Windissect CLI. It launches the existing
binary without a shell, streams stdout/stderr, and never changes Windissect's
verified-versus-candidate trust model.

Launching `windissect` with no arguments opens the file picker. It discovers
PE files in the current directory by checking their `MZ` signature. The
**Analyze everything** workflow produces IR, strings, assembly, bindings,
evidence, docs and—when IDA/Hex-Rays is installed—candidate C-like pseudocode.
Generated pseudocode can be read and scrolled inside the terminal.

The directory from which `windissect` was launched is the workspace root; it
is displayed in the TUI header and used for all relative output paths.

The **Browse functions** workflow is the main exploration surface:

- toggle candidate-only versus all recovered functions;
- select a function by RVA/name;
- inspect provenance, confidence, calls, imports and decoded assembly;
- press `d` to decompile that exact function;
- read the candidate C output without leaving the terminal.

```powershell
cd tui
npm install
npm run dev
```

The frontend searches for the executable in this order:

1. `--bin <path>`
2. `WINDISSECT_BIN`
3. `target/release/windissect.exe`
4. `target/debug/windissect.exe`
5. the repository root and then `PATH`

Examples:

```powershell
npm run dev -- --bin ..\target\release\windissect.exe
$env:WINDISSECT_BIN = 'D:\tools\windissect.exe'
npm run dev
```
