"""Builds the installer's wizard images from the Elytra mascot PNGs.

usage: python -I packaging/make-installer-art.py

Writes packaging/installer/wizard-{100,200}.bmp (welcome page, 164x314 at 100%)
and wizard-small-{100,200}.bmp (page header, 55x55 at 100%). Inno Setup picks
the size that matches the display scaling.
"""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
MASCOT = os.path.join(HERE, "..", "gui", "assets", "brand", "mascot")
OUT = os.path.join(HERE, "installer")
PANEL, WHITE = (231, 237, 254), (255, 255, 255)  # soft tint of the brand blue #5b84f7


def mascot(name, size):
    im = Image.open(os.path.join(MASCOT, name)).convert("RGBA")
    return im.resize((size, size), Image.Resampling.LANCZOS)


def flatten(canvas, bg):
    base = Image.new("RGB", canvas.size, bg)
    base.paste(canvas, mask=canvas.split()[3])
    return base


def wizard(scale):
    w, h = 164 * scale, 314 * scale
    canvas = Image.new("RGBA", (w, h), PANEL + (255,))
    ImageDraw.Draw(canvas).rectangle([0, h - 6 * scale, w, h], fill=(91, 132, 247, 255))
    m = mascot("elytra-wave.png", 136 * scale)
    canvas.alpha_composite(m, ((w - m.width) // 2, h - m.height - 22 * scale))
    return flatten(canvas, PANEL)


def small(scale):
    s = 55 * scale
    canvas = Image.new("RGBA", (s, s), WHITE + (255,))
    m = mascot("elytra-idle.png", s)
    canvas.alpha_composite(m, (0, 0))
    return flatten(canvas, WHITE)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for scale, tag in ((1, "100"), (2, "200")):
        wizard(scale).save(os.path.join(OUT, f"wizard-{tag}.bmp"))
        small(scale).save(os.path.join(OUT, f"wizard-small-{tag}.bmp"))
    print("ok", OUT)
