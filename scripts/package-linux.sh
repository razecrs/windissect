#!/usr/bin/env bash
# Build and package the Linux x86-64 distribution:
#   dist/Windissect-v<version>-linux-x64.tar.gz (+ .sha256, sha256sum format)
#
# The CLI is a static musl binary, the fleet is pure Go (CGO off), and the
# desktop app links glibc, so build the release on the oldest distribution it
# should run on (CI uses ubuntu-22.04).
#
# Usage: scripts/package-linux.sh [--version X.Y.Z]
# Honours CARGO_TARGET_DIR and DIST_DIR (default: dist/). Needs: cargo with the x86_64-unknown-linux-musl
# target, go, and the GPUI build libraries (see .github/workflows/release-linux.yml).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a value}"; shift 2 ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$version" ]; then
    version="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$repo/Cargo.toml" | head -n1)"
    [ -n "$version" ] || { echo "could not read the version from $repo/Cargo.toml" >&2; exit 1; }
fi
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'; then
    echo "invalid distribution version: $version" >&2
    exit 1
fi

musl=x86_64-unknown-linux-musl
target_dir="${CARGO_TARGET_DIR:-$repo/target}"
dist="${DIST_DIR:-$repo/dist}"
name="Windissect-v$version-linux-x64"
stage="$dist/$name"
tarball="$dist/$name.tar.gz"

cd "$repo"

echo "==> CLI (static, $musl)"
cargo build --release --locked -p windissect --bin windissect --target "$musl"
cli="$target_dir/$musl/release/windissect"

echo "==> desktop app"
cargo build --release --locked -p windissect-gui --bin windissect-gui
gui="$target_dir/release/windissect-gui"

echo "==> fleet driver"
mkdir -p "$target_dir/release"
fleet="$target_dir/release/windissect-fleet"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$fleet" ./cmd/windissect

echo "==> TUI (standalone, Bun)"
tui="$target_dir/release/windissect-tui"
(cd tui && npm ci --no-audit --no-fund && bun build-exe.ts bun-linux-x64 "$tui")

echo "==> smoke tests"
reported="$("$cli" --version)"
case "$reported" in
    *" $version" | "$version") ;;
    *) echo "CLI version mismatch: expected $version, got '$reported'" >&2; exit 1 ;;
esac
"$fleet" --help >/dev/null 2>&1 || { echo "fleet --help failed" >&2; exit 1; }
if command -v file >/dev/null 2>&1; then
    file "$cli" | grep -Eq 'static(ally|-pie) linked' || { echo "CLI is not statically linked: $(file "$cli")" >&2; exit 1; }
fi

echo "==> staging $stage"
case "$stage" in "$dist"/?*) ;; *) echo "refusing to stage outside $dist" >&2; exit 1 ;; esac
rm -rf "$stage"
mkdir -p "$stage"
install -m 755 "$cli" "$stage/windissect"
install -m 755 "$fleet" "$stage/windissect-fleet"
install -m 755 "$tui" "$stage/windissect-tui"
install -m 755 "$gui" "$stage/windissect-gui"
strip "$stage/windissect-gui" 2>/dev/null || true
install -m 755 packaging/linux/install.sh "$stage/install.sh"
install -m 644 packaging/linux/windissect.desktop "$stage/windissect.desktop"
install -m 644 gui/assets/brand/windissect-256.png "$stage/windissect.png"
install -m 644 packaging/linux/README.txt "$stage/README.txt"
install -m 644 LICENSE "$stage/LICENSE"

if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$stage/windissect.desktop"
fi

(cd "$stage" && find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum) > "$stage/SHA256SUMS.txt"

# Reproducible archive: fixed owner, order and timestamps (last commit time).
epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
rm -f "$tarball" "$tarball.sha256"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -C "$dist" -cf - "$name" | gzip -n -9 > "$tarball"
(cd "$dist" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")

echo "Distribution: $tarball ($(du -h "$tarball" | cut -f1))"
echo "SHA-256:      $(cut -d' ' -f1 "$tarball.sha256")"
