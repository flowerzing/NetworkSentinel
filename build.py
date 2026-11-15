#!/usr/bin/env python
"""Build script for NetSentinel Windows executable using PyInstaller."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def build() -> int:
    """Build the Windows executable."""
    project_root = Path(__file__).parent
    dist_dir = project_root / "dist"
    build_dir = project_root / "build"

    # Clean previous builds
    for dir_path in (dist_dir, build_dir):
        if dir_path.exists():
            shutil.rmtree(dir_path)

    # PyInstaller arguments
    args = [
        "pyinstaller",
        "--name=NetSentinel",
        "--windowed",  # No console window (GUI app)
        "--onefile",  # Single executable
        "--clean",
        "--noconfirm",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={project_root}",
        # Hidden imports for optional dependencies
        "--hidden-import=pyqtgraph",
        "--hidden-import=reportlab",
        "--hidden-import=scapy",
        "--hidden-import=nmap",
        # Data files
        f"--add-data={project_root / 'assets'};assets",
        f"--add-data={project_root / 'src/netsentinel/infrastructure/database/migrations.py'};netsentinel/infrastructure/database",
        # Entry point
        str(project_root / "main.py"),
    ]

    print("Building NetSentinel executable...")
    print(f"Command: {' '.join(args)}")

    result = subprocess.run(args, capture_output=True, text=True)

    if result.returncode != 0:
        print("Build failed!")
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        return result.returncode

    print("Build successful!")
    print(f"Executable: {dist_dir / 'NetSentinel.exe'}")

    # Verify the executable exists
    exe_path = dist_dir / "NetSentinel.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"Size: {size_mb:.1f} MB")
    else:
        print("Warning: Executable not found at expected path")

    return 0


if __name__ == "__main__":
    sys.exit(build())