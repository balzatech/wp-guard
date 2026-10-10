#!/usr/bin/env bash
# install.sh - install wp-guard for the current user (no root needed)
#
#   bash install.sh              install into ~/.local/share/wp-guard and link ~/.local/bin/wp-guard
#   bash install.sh --uninstall  remove both (your settings in ~/.wp_auditor are kept)
#
# Environment: PREFIX (default ~/.local) changes the install location.

set -eu
SRC=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
PREFIX=${PREFIX:-$HOME/.local}
DEST=$PREFIX/share/wp-guard
LINK=$PREFIX/bin/wp-guard

case "${1:-}" in
  ""|--uninstall) ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; [ "$1" = -h ] || [ "$1" = --help ] && exit 0; exit 64 ;;
esac

if [ "${1:-}" = "--uninstall" ]; then
  [ -L "$LINK" ] && rm -f "$LINK" && echo "Removed $LINK"
  if [ -d "$DEST" ]; then rm -rf "$DEST"; echo "Removed $DEST"; fi
  echo "Your settings and quarantines in ~/.wp_auditor were NOT touched."
  exit 0
fi

fail=0
need() { command -v "$1" >/dev/null 2>&1 || { echo "  missing: $1 - $2"; fail=1; }; }

echo "Checking requirements..."
[ "${BASH_VERSINFO[0]}" -ge 4 ] || { echo "  bash 4 or newer is required (found $BASH_VERSION)"; fail=1; }
for c in find awk grep sed sort xargs mktemp stat paste sha256sum readlink; do need "$c" "install GNU coreutils/findutils"; done
# GNU-only features the scripts rely on
find / -maxdepth 0 -printf '' 2>/dev/null || { echo "  find lacks -printf: GNU findutils is required (macOS/BSD is not supported)"; fail=1; }
stat -c %s "$SRC/VERSION" >/dev/null 2>&1 || { echo "  stat lacks -c: GNU coreutils is required (macOS/BSD is not supported)"; fail=1; }
[ "$fail" = 0 ] || { echo "Cannot install: fix the items above."; exit 1; }
command -v curl >/dev/null 2>&1 || echo "  note: curl not found - HTTP checks and Slack/Discord/ntfy alerts will not work"
command -v wp >/dev/null 2>&1 || echo "  note: wp-cli not found - database checks and official checksums will be skipped (https://wp-cli.org)"

echo "Installing to $DEST ..."
mkdir -p "$DEST" "$PREFIX/bin"
for d in bin lib checks rules; do rm -rf "${DEST:?}/$d"; cp -R "$SRC/$d" "$DEST/$d"; done
cp "$SRC/VERSION" "$SRC/LICENSE" "$SRC/README.md" "$DEST/" 2>/dev/null || true
chmod +x "$DEST"/bin/*
ln -sf "$DEST/bin/wp-guard" "$LINK"

echo "Installed wp-guard $(cat "$DEST/VERSION")  ->  $LINK"
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) echo "Add this to your ~/.bashrc so the command is found:  export PATH=\"$PREFIX/bin:\$PATH\"" ;; esac
echo
echo "Next, from your WordPress folder:"
echo "  wp-guard init     # guided setup (about 1 minute)"
echo "  wp-guard scan     # find problems"
