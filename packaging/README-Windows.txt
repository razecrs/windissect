Windissect for Windows
======================

Start here
----------

Double-click Windissect-GUI.exe for the desktop workbench.

Command-line users can run windissect.exe from PowerShell or Command Prompt.
Run it with no arguments for the interactive terminal UI (windissect-tui.exe,
no Node.js needed), or windissect --help for the commands.
windissect-fleet.exe manages exact-build PDB downloads and corpus processing;
the desktop workbench invokes it automatically when needed.

No installation or administrator access is required. Analysis outputs default
to %LOCALAPPDATA%\Windissect\workspace and can be changed in the workbench.

Discord Rich Presence
---------------------

Presence works automatically when the Discord desktop client is running. It
uses Discord's local IPC pipe; no bot installation, login, or token is needed.
The toggle and module-name privacy setting are under Tools in the workbench.

Integrity and source
--------------------

SHA256SUMS.txt contains hashes for every distributed file. The source and
license are available at https://github.com/razecrs/windissect.

This is an unsigned portable build. Windows SmartScreen can warn for a newly
published binary until it has reputation or is code-signed.
