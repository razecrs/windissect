#!/usr/bin/env bash
# Per-user install of Windissect from an extracted release folder. No root.
#
#   ./install.sh              install (or upgrade in place)
#   ./install.sh --uninstall  remove exactly the files install put down
#
# Binaries go to ~/.local/bin, the menu entry to ~/.local/share/applications
# and the icon to ~/.local/share/icons/hicolor/256x256/apps (XDG_DATA_HOME is
# honoured). The CLI, fleet and desktop app stay side by side, which is where
# the desktop app looks for them. Settings (~/.config/Windissect) and the
# analysis workspace are never touched.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin_dir="$HOME/.local/bin"
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
app_dir="$data_dir/applications"
icon_dir="$data_dir/icons/hicolor/256x256/apps"
binaries=(windissect windissect-fleet windissect-gui)

refresh_caches() {
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q "$app_dir" 2>/dev/null || true
    fi
    # Only refresh an icon cache that already exists; creating one in the
    # user's hicolor folder would leave a file behind after uninstall.
    if [ -f "$data_dir/icons/hicolor/icon-theme.cache" ] && command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f "$data_dir/icons/hicolor" 2>/dev/null || true
    fi
}

uninstall() {
    for b in "${binaries[@]}"; do rm -f "$bin_dir/$b"; done
    rm -f "$app_dir/windissect.desktop" "$icon_dir/windissect.png"
    refresh_caches
    echo "Windissect removed. Settings in ${XDG_CONFIG_HOME:-$HOME/.config}/Windissect and the workspace (${XDG_DATA_HOME:-$HOME/.local/share}/Windissect) were kept."
}

install_all() {
    for f in "${binaries[@]}" windissect.desktop windissect.png; do
        [ -f "$here/$f" ] || { echo "missing $here/$f; run install.sh from the extracted release folder" >&2; exit 1; }
    done
    mkdir -p "$bin_dir" "$app_dir" "$icon_dir"
    for b in "${binaries[@]}"; do install -m 755 "$here/$b" "$bin_dir/$b"; done
    install -m 644 "$here/windissect.png" "$icon_dir/windissect.png"
    # Point the menu entry at the installed binary, so it works even when
    # ~/.local/bin is not on the desktop session's PATH.
    sed -e "s|^Exec=windissect-gui|Exec=$bin_dir/windissect-gui|" \
        -e "s|^TryExec=windissect-gui|TryExec=$bin_dir/windissect-gui|" \
        "$here/windissect.desktop" > "$app_dir/windissect.desktop"
    chmod 644 "$app_dir/windissect.desktop"
    refresh_caches

    echo "Installed windissect, windissect-fleet and windissect-gui to $bin_dir"
    echo "Menu entry: $app_dir/windissect.desktop"
    case ":$PATH:" in
        *":$bin_dir:"*) ;;
        *) echo "Note: $bin_dir is not on PATH; add it to use the CLI from a shell." ;;
    esac
}

case "${1:-}" in
    "") install_all ;;
    --uninstall|uninstall) uninstall ;;
    -h|--help) sed -n '2,11p' "$0" ;;
    *) echo "unknown argument: $1 (use --uninstall or no argument)" >&2; exit 2 ;;
esac
