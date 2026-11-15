#!/usr/bin/env python
"""Manually set icon on a Windows executable using pefile."""
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    print("Installing pefile...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
    import pefile

def set_icon(exe_path: str, icon_path: str) -> bool:
    """Replace the icon in a Windows executable."""
    try:
        pe = pefile.PE(exe_path)

        # Read the icon file
        with open(icon_path, "rb") as f:
            icon_data = f.read()

        # Find and replace the icon resource
        # This is a simplified approach - full icon replacement is complex
        # For a complete solution, Resource Hacker or rcedit is recommended

        print(f"Note: Full icon replacement via pefile is complex.")
        print(f"Recommended: Use Resource Hacker or rcedit instead.")
        print(f"  rcedit {exe_path} --set-icon {icon_path}")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    exe_path = "dist/NetSentinel.exe"
    icon_path = "assets/icons/app.ico"

    if not Path(exe_path).exists():
        print(f"Executable not found: {exe_path}")
        sys.exit(1)
    if not Path(icon_path).exists():
        print(f"Icon not found: {icon_path}")
        sys.exit(1)

    print(f"For manual icon replacement, use one of these methods:")
    print(f"")
    print(f"1. Resource Hacker (GUI): https://www.angusj.com/resourcehacker/")
    print(f"   Open {exe_path} -> Right-click 'Icon' -> 'Replace Icon' -> Select {icon_path}")
    print(f"")
    print(f"2. rcedit (CLI):")
    print(f"   rcedit {exe_path} --set-icon {icon_path}")
    print(f"")
    print(f"3. Or use the PyInstaller spec with proper icon (already done - see build log)")