#!/usr/bin/env python3
"""Generate RedGuard app icons — red shield with RG text."""
from PIL import Image, ImageDraw, ImageFont
import os, math

ICONS_DIR = os.path.join(os.path.dirname(__file__), "../app/src-tauri/icons")
os.makedirs(ICONS_DIR, exist_ok=True)

RED    = (220, 38, 38, 255)
DARK   = (180, 20, 20, 255)
WHITE  = (255, 255, 255, 255)
TRANSP = (0, 0, 0, 0)


def shield_points(size):
    """Pentagon shield vertices scaled to given size."""
    m = size * 0.08
    w, h = size - m * 2, size - m * 2
    ox, oy = m, m
    return [
        (ox + w * 0.0,  oy + h * 0.0),   # top-left
        (ox + w * 1.0,  oy + h * 0.0),   # top-right
        (ox + w * 1.0,  oy + h * 0.58),  # right
        (ox + w * 0.5,  oy + h * 1.0),   # bottom point
        (ox + w * 0.0,  oy + h * 0.58),  # left
    ]


def rounded_polygon(draw, points, radius, fill):
    """Draw a polygon with rounded corners."""
    draw.polygon(points, fill=fill)
    # Draw circles at each corner to round them
    r = radius
    for (x, y) in points:
        draw.ellipse([x - r, y - r, x + r, y + r], fill=fill)


def make_icon(size, for_tray=False):
    img = Image.new("RGBA", (size, size), TRANSP)
    draw = ImageDraw.Draw(img)

    if for_tray:
        # Tray: solid white shield (dark bg comes from OS)
        pts = shield_points(size)
        draw.polygon(pts, fill=WHITE)
        return img

    # Main icon: red rounded square background
    r = max(4, size // 5)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=RED)

    # Slightly darker inner shield shape
    inner = size * 0.82
    offset = (size - inner) / 2
    scaled = [
        (offset + (x - offset * 0) * (inner / size),
         offset + (y - offset * 0) * (inner / size))
        for x, y in shield_points(size)
    ]
    pts = shield_points(int(inner))
    pts2 = [(x + offset, y + offset) for x, y in pts]
    draw.polygon(pts2, fill=DARK)

    # "RG" text
    font_size = max(8, int(size * 0.30))
    font = None
    for fp in [
        "/System/Library/Fonts/HelveticaNeue.ttc",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ]:
        try:
            font = ImageFont.truetype(fp, font_size)
            break
        except Exception:
            pass
    if font is None:
        font = ImageFont.load_default()

    text = "RG"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (size - tw) // 2 - bbox[0]
    ty = int(size * 0.38) - bbox[1]
    draw.text((tx, ty), text, fill=WHITE, font=font)

    return img


# ── Generate all required sizes ───────────────────────────────────────────────

specs = [
    (32,  "32x32.png",        False),
    (128, "128x128.png",      False),
    (256, "128x128@2x.png",   False),
    (512, "icon.png",         False),
    (22,  "tray-icon.png",    True),
]

for size, name, tray in specs:
    img = make_icon(size, for_tray=tray)
    path = os.path.join(ICONS_DIR, name)
    img.save(path)
    print(f"  {path}")

# ICO — embed multiple sizes for Windows
ico_images = [make_icon(s) for s in [256, 128, 64, 48, 32, 24, 16]]
ico_path = os.path.join(ICONS_DIR, "icon.ico")
ico_images[0].save(
    ico_path, format="ICO",
    append_images=ico_images[1:],
    sizes=[(s, s) for s in [256, 128, 64, 48, 32, 24, 16]],
)
print(f"  {ico_path}")
print("\nDone — all icons generated.")
