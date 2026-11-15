# -*- mode: python ; coding: utf-8 -*-

"""PyInstaller spec file for NetSentinel."""

import sys
from pathlib import Path

# When running from PyInstaller, __file__ is not defined in the spec namespace.
# Use sys.argv[0] or a known path instead.
project_root = Path.cwd()

# Collect data files
def collect_data_files():
    data_files = []

    # Assets directory
    assets_dir = project_root / "assets"
    if assets_dir.exists():
        for file_path in assets_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(project_root)
                data_files.append((str(file_path), str(rel_path.parent)))

    return data_files

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root / "src")],
    binaries=[],
    datas=collect_data_files(),
    hiddenimports=[
        "pyqtgraph",
        "reportlab",
        "reportlab.lib.colors",
        "reportlab.lib.pagesizes",
        "reportlab.lib.styles",
        "reportlab.lib.units",
        "reportlab.platypus",
        "scapy",
        "scapy.all",
        "scapy.layers.l2",
        "scapy.layers.inet",
        "nmap",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy.testing",
        "pandas",
        "pytest",
        "ruff",
        "mypy",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="NetSentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI application - no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / "assets" / "icons" / "app.ico") if (project_root / "assets" / "icons" / "app.ico").exists() else None,
    version=str(version_file),
)