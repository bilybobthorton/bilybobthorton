#!/usr/bin/env python3
"""
Generate RedGuard app icons.
Supersampling (4x then LANCZOS downsample) gives smooth anti-aliased edges.
Design: red rounded rectangle, bold white 'RG' centered.
"""
import os
from PIL import Image, ImageDraw, ImageFont

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "src-tauri", "icons")
os.makedirs(OUT_DIR, exist_ok=True)

RED    = (220, 38, 38, 255)
WHITE  = (255, 255, 255, 255)
TRANSP = (0, 0, 0, 0)

FONT_CANDIDATES = [
    # macOS
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial Bold.ttf",
    # Linux
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    # Windows
    "C:/Windows/Fonts/arialbd.ttf",
]


def load_font(size):
    for path in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def draw_icon(target_size: int, scale: int = 4) -> Image.Image:
    """Draw at 4× then downsample for crisp anti-aliased result."""
    s = target_size * scale
    img = Image.new("RGBA", (s, s), TRANSP)
    draw = ImageDraw.Draw(img)

    pad    = round(s * 0.08)
    radius = round(s * 0.22)

    # Red rounded rectangle background
    draw.rounded_rectangle([pad, pad, s - pad, s - pad], radius=radius, fill=RED)

    # "RG" text (single "R" at very small sizes where two chars blur)
    text      = "RG" if target_size >= 48 else "R"
    font_size = round(s * 0.35) if target_size >= 48 else round(s * 0.52)
    font      = load_font(font_size)

    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        tw   = bbox[2] - bbox[0]
        th   = bbox[3] - bbox[1]
        tx   = (s - tw) // 2 - bbox[0]
        ty   = (s - th) // 2 - bbox[1]
    except AttributeError:                          # PIL < 9.2
        tw, th = draw.textsize(text, font=font)    # type: ignore
        tx = (s - tw) // 2
        ty = (s - th) // 2

    draw.text((tx, ty), text, font=font, fill=WHITE)

    return img.resize((target_size, target_size), Image.LANCZOS)


def make_tray_icon(size: int = 32) -> Image.Image:
    """
    System-tray icon: transparent bg, red circle with white 'R'.
    Keeps the icon visible on both light and dark taskbars.
    """
    s = size * 4
    img  = Image.new("RGBA", (s, s), TRANSP)
    draw = ImageDraw.Draw(img)
    cx   = s // 2
    r    = round(s * 0.46)
    draw.ellipse([cx - r, cx - r, cx + r, cx + r], fill=RED)

    font_size = round(s * 0.50)
    font      = load_font(font_size)
    text      = "R"
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        tw   = bbox[2] - bbox[0]
        th   = bbox[3] - bbox[1]
        tx   = cx - tw // 2 - bbox[0]
        ty   = cx - th // 2 - bbox[1]
    except AttributeError:
        tw, th = draw.textsize(text, font=font)   # type: ignore
        tx = cx - tw // 2
        ty = cx - th // 2
    draw.text((tx, ty), text, font=font, fill=WHITE)

    return img.resize((size, size), Image.LANCZOS)


def save(img: Image.Image, name: str):
    path = os.path.join(OUT_DIR, name)
    img.save(path)
    print(f"  ✓  {name}  ({img.size[0]}×{img.size[1]})")


print("Generating RedGuard icons (supersampled)…\n")

save(draw_icon(32),  "32x32.png")
save(draw_icon(128), "128x128.png")
save(draw_icon(256), "128x128@2x.png")
save(draw_icon(512), "icon.png")
save(make_tray_icon(32), "tray-icon.png")

# Windows .ico — multiple sizes in one file
ico_sizes  = [256, 128, 64, 48, 32, 24, 16]
ico_frames = [draw_icon(sz) for sz in ico_sizes]
ico_path   = os.path.join(OUT_DIR, "icon.ico")
ico_frames[0].save(
    ico_path,
    format="ICO",
    sizes=[(sz, sz) for sz in ico_sizes],
    append_images=ico_frames[1:],
)
print(f"  ✓  icon.ico  ({', '.join(str(s) for s in ico_sizes)})")
print("\nDone.")
