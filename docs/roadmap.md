# Roadmap

Planned work that is not a bug. Bugs and limits live in
[known-issues.md](known-issues.md).

## Linux desktop app

The CLI and the fleet already run on Linux, including the PDB download, and
pass the same verify checks as on Windows. The desktop app runs there too, with
its own title bar and a zenity or kdialog fallback for the file dialog. Still
missing:

- **Resize from the window edges.** Client-decorated windows have to handle
  this themselves; for now, only maximize works.
- **Discord status.** On Linux, Discord listens on a Unix socket
  (`$XDG_RUNTIME_DIR/discord-ipc-N`) rather than a named pipe.
- **Machine DLL list.** "List Windows DLLs" reads System32, so it is empty on
  Linux. It could read a mounted Windows partition or a folder the user picks.
- **Packaging.** Ship the GUI in the Linux tarball, plus a `.desktop` file and
  icon.

## v1.5.0: Settings and appearance

The desktop app ships with one fixed look. The theme is hard-coded to dark
(`gui/src/main.rs`, `Theme::change(ThemeMode::Dark, ..)`), and the code font is
the `MONO` constant (`"Cascadia Mono"` in `gui/src/shell.rs`). There is nowhere
for a user to change either.

- **Settings page.** Add a gear to the activity bar, under Tools. It opens
  Settings as a sidebar section or an editor tab, like Docs and Tools.
- **Light mode.** Offer Light, Dark and System, where System follows Windows'
  app theme and switches live when Windows changes. Every hand-picked colour in
  `shell.rs` has to come from the theme so that nothing stays dark-on-dark or
  light-on-light.
- **Code font.** Let the user pick the monospace font and its size for code,
  the output panel and tables. Keep Cascadia Mono as the default and fall back
  to Consolas when the chosen font is missing.
- **Themes.** Add a few built-in presets (the default Windissect blue, a
  high-contrast one, and one or two more) plus an accent colour.
- **Background blur.** Add an optional Mica or Acrylic window backdrop on
  Windows 11, with a solid fallback on Windows 10 or when transparency effects
  are turned off. Text has to stay readable over any wallpaper.
- **Persist settings.** Save them to `%APPDATA%\Windissect\settings.json` and
  apply them before the first frame, so the window never flashes the wrong
  theme.
- **More docs.** The Docs sidebar shows only "Start here" until a module is
  analysed. Add pages for the tabs, verify, the workspace, the CLI and
  keyboard shortcuts.
