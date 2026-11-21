"""Draws the Elytra mascot in VectorCraft (headless) and exports SVG + PNG.

Like Ferris, the Go gopher and Clawd: one simple creature in the brand colour with a face,
nothing else. Beetle hints only: a seam down the back where the wing cases (elytra) meet,
at the logo's blade angle, and two short antennae. Flat colours, no glow, no shine.

usage: python -I elytra_vc.py <out-name> [pose]     pose: idle wave happy wow sleep pixel
"""
import math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vcmcp import VC
HERE = os.path.dirname(os.path.abspath(__file__))

BODY, DARK, INK, EYE = "#5b84f7", "#2f4fc0", "#0e1220", "#ffffff"

SHELL = "M60 352 C 60 222, 150 140, 256 140 C 362 140, 452 222, 452 352 C 452 412, 402 436, 256 436 C 110 436, 60 412, 60 352 Z"


def xl(y):  # blade angle (logo slope -56/256)
    return 272 - 0.21875 * (y - 200)


def ellipse_d(cx, cy, rx, ry, rot=0.0):
    k = 0.5522847498
    pts = [(rx, 0), (rx, ry * k), (rx * k, ry), (0, ry), (-rx * k, ry), (-rx, ry * k), (-rx, 0), (-rx, -ry * k),
           (-rx * k, -ry), (0, -ry), (rx * k, -ry), (rx, -ry * k), (rx, 0)]
    c, s = math.cos(math.radians(rot)), math.sin(math.radians(rot))
    P = [(cx + x * c - y * s, cy + x * s + y * c) for x, y in pts]
    d = f"M{P[0][0]:.2f} {P[0][1]:.2f}"
    for i in range(1, 13, 3):
        d += " C " + ", ".join(f"{P[j][0]:.2f} {P[j][1]:.2f}" for j in (i, i + 1, i + 2))
    return d + " Z"


class Draw:
    def __init__(self, v):
        self.v = v

    def path(self, d, **kw):
        return self.v.tool("draw_path", d=d, **kw)["id"]

    def clip(self, ids, clip_d):
        cid = self.path(clip_d, fill="#000000", stroke="none")
        return self.v.run("object.clippingMask.make", ids=ids + [cid])["id"]


def face(D, eyes, mouth, cy=318):
    for x in (206, 306):
        if eyes in ("open", "wow"):
            r = (24, 30) if eyes == "open" else (28, 34)
            D.path(ellipse_d(x, cy, *r), fill=INK, stroke="none")
            D.path(ellipse_d(x + 8, cy - 11, 8.5, 8.5), fill=EYE, stroke="none")
        elif eyes == "happy":
            D.path(f"M{x-20} {cy+8} Q{x} {cy-22} {x+20} {cy+8}", fill="none", stroke=INK, strokeWidth=12, cap="round")
        elif eyes == "shut":
            D.path(f"M{x-20} {cy} Q{x} {cy+15} {x+20} {cy}", fill="none", stroke=INK, strokeWidth=10, cap="round")
    if mouth == "smile":
        D.path(f"M240 {cy+48} Q256 {cy+62} 272 {cy+48}", fill="none", stroke=INK, strokeWidth=9, cap="round")
    elif mouth == "grin":
        D.path(f"M230 {cy+42} Q256 {cy+80} 282 {cy+42} Z", fill=INK, stroke=INK, strokeWidth=5, join="round")
    elif mouth == "o":
        D.path(ellipse_d(256, cy + 56, 10, 13), fill=INK, stroke="none")


def build(v, pose="idle"):
    D = Draw(v)
    v.run("file.new", width=512, height=512, units="Pixels", backgroundContents="transparent")
    # stubby feet and arm nubs
    for x in (182, 330):
        D.path(ellipse_d(x, 436, 42, 20), fill=DARK, stroke="none")
    D.path(ellipse_d(66, 366, 22, 34, 24), fill=DARK, stroke="none")
    D.path(ellipse_d(452, 290, 22, 36, 34) if pose == "wave" else ellipse_d(446, 366, 22, 34, -24), fill=DARK, stroke="none")
    # short antennae
    for d in ("M214 150 C 206 118, 190 100, 168 94", "M298 150 C 306 118, 322 100, 344 94"):
        D.path(d, fill="none", stroke=DARK, strokeWidth=14, cap="round")
    for x in (166, 346):
        D.path(ellipse_d(x, 93, 14, 14), fill=DARK, stroke="none")
    # body + the seam where the wing cases meet
    D.path(SHELL, fill=BODY, stroke="none")
    D.clip([D.path(f"M{xl(120):.1f} 120 L{xl(262):.1f} 262", fill="none", stroke=DARK, strokeWidth=11, cap="round")], SHELL)

    eyes, mouth = {"idle": ("open", "smile"), "wave": ("happy", "grin"), "happy": ("happy", "grin"),
                   "wow": ("wow", "o"), "sleep": ("shut", "o")}[pose]
    face(D, eyes, mouth)


# Clawd-style pixel version (16 x 14). B body, D dark, E eye, W eye glint, S seam.
PIXELS = [
    "....D......D....",
    ".....D....D.....",
    "....BBBBBSBB....",
    "...BBBBBBSBBB...",
    "..BBBBBBSBBBBB..",
    "..BBBBBBSBBBBB..",
    ".DBBBBBBBBBBBBD.",
    "D.BBEWBBBBEWBB.D",
    "..BBEEBBBBEEBB..",
    "..BBBBBBBBBBBB..",
    ".DBBBBBEEBBBBBD.",
    "D.BBBBBBBBBBBB.D",
    "...BBBBBBBBBB...",
    "...DD......DD...",
]


def build_pixel(v):
    D = Draw(v)
    v.run("file.new", width=512, height=512, units="Pixels", backgroundContents="transparent")
    c, ox, oy = 30, 16, 46
    col = {"B": BODY, "D": DARK, "E": INK, "W": EYE, "S": DARK}
    for r, row in enumerate(PIXELS):
        for k, ch in enumerate(row):
            if ch in col:
                x, y = ox + k * c, oy + r * c
                D.path(f"M{x} {y} L{x+c} {y} L{x+c} {y+c} L{x} {y+c} Z", fill=col[ch], stroke="none")


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "elytra"
    pose = sys.argv[2] if len(sys.argv) > 2 else "idle"
    v = VC()
    try:
        build_pixel(v) if pose == "pixel" else build(v, pose)
        v.tool("export", path=os.path.join(HERE, name + ".svg"))
        v.tool("export", path=os.path.join(HERE, name + ".png"), options={"ppi": 72, "background": "transparent"})
        print("ok", name)
    finally:
        v.close()
