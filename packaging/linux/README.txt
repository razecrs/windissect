Windissect for Linux (x86-64)
=============================

What is in this folder
----------------------

  windissect-gui     desktop workbench (needs a Wayland or X11 session)
  windissect         command-line analyzer, statically linked, runs anywhere
  windissect-fleet   exact-build PDB downloads and corpus processing
  windissect-tui     interactive terminal UI; `windissect` with no arguments
                     starts it (no Node.js needed)
  install.sh         optional per-user install, no root needed
  windissect.desktop menu entry, windissect.png its icon
  SHA256SUMS.txt     hashes of every file here

Run without installing
----------------------

  ./windissect-gui
  ./windissect --help
  ./windissect-fleet --help

Keep the three programs in the same folder: the desktop app looks for
windissect and windissect-fleet beside itself.

Install for this user
---------------------

  ./install.sh               # ~/.local/bin, menu entry and icon
  ./install.sh --uninstall   # removes exactly those files

Settings live in ~/.config/Windissect and the analysis workspace defaults to
~/.local/share/Windissect/workspace (both follow XDG_CONFIG_HOME and
XDG_DATA_HOME). Uninstalling keeps them.

Desktop app requirements
------------------------

A glibc-based distribution from 2022 or later (built on Ubuntu 22.04), a
Vulkan driver (Mesa is enough), libxcb, libxkbcommon and libxkbcommon-x11,
plus fontconfig and, for Wayland sessions, libwayland-client. File
dialogs use the XDG desktop portal, falling back to zenity or kdialog. WSLg on
Windows 11 works.

What works on Linux
-------------------

Static analysis is platform independent: extract, verify, emit headers, Rust
bindings and symbols, strings, history and diffs all work on Windows binaries
copied to this machine, and the fleet downloads their PDBs from the Microsoft
symbol server.

Windows only:
  - runtime semantic probing: refine --semantic loads the target DLL to
    observe it, so on Linux it falls back to static evidence only;
  - decompile, which drives IDA Pro / Hex-Rays and only finds an IDA
    install by itself on Windows (IDA_PATH can point at idat elsewhere, but
    only the Windows setup is tested).

Source and license
------------------

AGPL-3.0-only, see LICENSE. Source: https://github.com/razecrs/windissect
