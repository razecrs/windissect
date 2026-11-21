# Elytra

Windissect's mascot: a small blue beetle. Like Ferris and the Go gopher, it's one simple creature in the
brand colour with a face, with no logo on it. Its only beetle hints are two short antennae and a seam down its back
where the wing cases (elytra) meet, drawn at the logo's blade angle.

| File | Use |
|---|---|
| `elytra-idle` | Default |
| `elytra-wave`, `-happy`, `-wow`, `-sleep` | Emotes / reactions |
| `elytra-pixel` | 16x14 pixel version for the CLI and terminal |
| `elytra-avatar.png` | On the navy tile, for Discord and profile pictures |
| `elytra-vc-sheet.png` | Overview |

Colours: body `#5b84f7`, limbs and seam `#2f4fc0`, eyes `#0e1220`. Flat: no gradients, glow or shine.

Regenerate (VectorCraft 0.24.1, headless MCP; set `VECTORCRAFT_CLI` to the CLI path, default in `vcmcp.py`):

```
python -I elytra_vc.py elytra-idle idle     # poses: idle wave happy wow sleep pixel
```
