"""
generate_icons.py — Create shield PNG icons for the DNS Shield extension.
Uses Pillow to draw a simple shield shape at 16, 48, and 128 pixels.
Run once from the extension directory: python generate_icons.py
"""

import os
from PIL import Image, ImageDraw

ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons')
os.makedirs(ICONS_DIR, exist_ok=True)


def create_shield(size):
    """Draw a green shield with a white checkmark at the given pixel size."""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Proportional margins
    m = max(1, int(size * 0.06))
    cx = size / 2

    # Shield outline points
    top_y      = m
    shoulder_y = m + (size - 2 * m) * 0.15
    waist_y    = m + (size - 2 * m) * 0.55
    bottom_y   = size - m

    shield = [
        (cx, top_y),
        (size - m, shoulder_y),
        (size - m, waist_y),
        (cx, bottom_y),
        (m, waist_y),
        (m, shoulder_y),
    ]
    # Outer dark-green shield
    draw.polygon(shield, fill=(0, 168, 80, 255))

    # Inner lighter shield
    im = max(2, int(size * 0.14))
    itop      = im + 2
    ishoulder = im + (size - 2 * im) * 0.15
    iwaist    = im + (size - 2 * im) * 0.50
    ibottom   = size - im - max(1, int(size * 0.06))

    inner = [
        (cx, itop),
        (size - im, ishoulder),
        (size - im, iwaist),
        (cx, ibottom),
        (im, iwaist),
        (im, ishoulder),
    ]
    draw.polygon(inner, fill=(0, 230, 118, 255))

    # White checkmark (only if large enough)
    if size >= 24:
        cs = size * 0.18
        cy = m + (size - 2 * m) * 0.38
        pts = [
            (cx - cs * 0.55, cy + cs * 0.05),
            (cx - cs * 0.05, cy + cs * 0.50),
            (cx + cs * 0.55, cy - cs * 0.35),
        ]
        lw = max(2, int(size * 0.06))
        draw.line(pts, fill=(255, 255, 255, 230), width=lw, joint='curve')

    return img


for s in (16, 48, 128):
    img = create_shield(s)
    path = os.path.join(ICONS_DIR, f'icon{s}.png')
    img.save(path)
    print(f'Created {path}')

print('Done!')
