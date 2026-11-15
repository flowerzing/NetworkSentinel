#!/usr/bin/env python
"""Create a proper Windows .ico with all required sizes from existing icon."""
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
    from PIL import Image

icon_path = Path("assets/icons/app.ico")
backup_path = Path("assets/icons/app.ico.backup")

# Backup original
if icon_path.exists() and not backup_path.exists():
    icon_path.rename(backup_path)
    print(f"Backed up original to {backup_path}")

# Open the original (will load the largest available size)
with Image.open(backup_path) as img:
    # Convert to RGBA if needed
    if img.mode != "RGBA":
        img = img.convert("RGBA")

    # Windows standard icon sizes
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

    # Create images for each size with high-quality resampling
    icon_images = []
    for size in sizes:
        resized = img.resize(size, Image.Resampling.LANCZOS)
        icon_images.append(resized)

    # Save as proper .ico with all sizes
    icon_images[0].save(
        icon_path,
        format="ICO",
        sizes=[(img.width, img.height) for img in icon_images],
        append_images=icon_images[1:]
    )

print(f"Created {icon_path} with sizes: {sizes}")
print("Rebuild with: python -m PyInstaller NetSentinel.spec")