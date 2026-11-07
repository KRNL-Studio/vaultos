#!/usr/bin/env bash
# Install a packaged VaultOS Linux build for the current user.
#
#   scripts/install-linux.sh [--from DIR|ARCHIVE] [--prefix DIR] [--enable-service]
#
#   --from DIR|ARCHIVE  build folder or .tar.gz from `npm run dist:linux`
#                       (default: dist/vaultos-preview-linux-<arch> in this checkout)
#   --prefix DIR        absolute install folder (default: ~/.local/opt/vaultos-preview)
#   --enable-service    write, enable and start the systemd user unit that runs the installed
#                       app with --service (background access; see docs/AGENTS.md)
#
# Nothing runs as root; without --enable-service no service is written. Vault data is never
# touched: it stays in ~/.config/VaultOS-Preview (or VAULTOS_DATA_DIR). The app needs the
# system's WebKitGTK 4.1 and, for the menu bar item, libayatana-appindicator3.
set -euo pipefail

die() { echo "install-linux: $*" >&2; exit 1; }

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
from="" prefix="$HOME/.local/opt/vaultos-preview" enable_service=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) [[ $# -ge 2 ]] || die "--from needs a value"; from="$2"; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || die "--prefix needs a value"; prefix="$2"; shift 2 ;;
    --enable-service) enable_service=1; shift ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ "$(uname -s)" == Linux ]] || die "this installer is for Linux"

# Paths end up in a .desktop Exec line and a systemd unit, which give these characters meaning.
safe_path() {
  [[ "$1" == /* ]] || die "$2 must be an absolute path: $1"
  case "$1" in *[\"\\\`\$%\&\|]*|*$'\n'*) die "$2 contains characters that cannot be written safely: $1" ;; esac
}

xdg_dir() { if [[ -n "${!1:-}" && "${!1}" == /* ]]; then printf '%s' "${!1}"; else printf '%s' "$2"; fi; }

case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

prefix="${prefix%/}"
safe_path "$prefix" "--prefix"
[[ "$prefix" != "$HOME" && "$prefix" != "$(dirname "$HOME")" && "$prefix" == /*/* ]] || die "refusing to install into $prefix"
desktop_file="$(xdg_dir XDG_DATA_HOME "$HOME/.local/share")/applications/org.vaultos.preview.desktop"
unit_file="$(xdg_dir XDG_CONFIG_HOME "$HOME/.config")/systemd/user/vaultos-preview-backend.service"

# Never replace a folder that is not a previous VaultOS install (this one, or the earlier
# 0.2 Electron build with its resources/app.asar).
if [[ -e "$prefix" ]]; then
  [[ -d "$prefix" ]] || die "$prefix exists and is not a folder"
  if [[ -n "$(ls -A "$prefix")" && ! ( -x "$prefix/vaultos-preview" && ( -x "$prefix/vaultosd" || -f "$prefix/resources/app.asar" ) ) ]]; then
    die "$prefix is not empty and is not a VaultOS install; choose another --prefix"
  fi
  if command -v pgrep >/dev/null 2>&1 && pgrep -f -- "$prefix/vaultos-preview" >/dev/null 2>&1; then
    die "VaultOS is running from $prefix; quit it (and stop its service) and retry"
  fi
fi

tmp="$(mktemp -d)" staging=""
trap 'rm -rf "$tmp" ${staging:+"$staging"}' EXIT

src="${from:-$repo/dist/vaultos-preview-linux-$arch}"
if [[ -f "$src" ]]; then
  if [[ -f "$src.sha256" ]]; then
    if command -v sha256sum >/dev/null; then sum=(sha256sum); else sum=(shasum -a 256); fi
    (cd "$(dirname "$src")" && "${sum[@]}" -c "$(basename "$src").sha256") || die "checksum mismatch for $src"
  else
    echo "note: no $(basename "$src").sha256 next to the archive; skipping checksum verification"
  fi
  tar -xzf "$src" -C "$tmp"
  src="$tmp/vaultos-preview-linux-$arch"
fi
for program in vaultos-preview vaultos vaultos-agent vaultos-mcp vaultosd; do
  [[ -x "$src/$program" ]] || die "no VaultOS linux-$arch build at $src ($program is missing); run 'npm run dist:linux' or pass --from"
done

mkdir -p "$(dirname "$prefix")"
staging="$(mktemp -d "$(dirname "$prefix")/.vaultos-preview-install.XXXXXX")"
cp -R "$src/." "$staging/"
chmod 755 "$staging"

if [[ -e "$prefix" ]]; then
  mv "$prefix" "$staging.old"
  mv "$staging" "$prefix"
  rm -rf "$staging.old"
else
  mv "$staging" "$prefix"
fi

mkdir -p "$(dirname "$desktop_file")"
cat > "$desktop_file.tmp" <<DESKTOP
[Desktop Entry]
Type=Application
Name=VaultOS
Comment=Local vault for project secrets with an MCP bridge for coding agents
Exec="$prefix/vaultos-preview"
Icon=$prefix/vaultos-preview.png
Terminal=false
Categories=Development;Utility;
DESKTOP
chmod 644 "$desktop_file.tmp"
mv -f "$desktop_file.tmp" "$desktop_file"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(dirname "$desktop_file")" >/dev/null 2>&1 || true

echo "installed:"
echo "  app       $prefix/vaultos-preview"
echo "  tools     $prefix/vaultos, vaultos-agent, vaultos-mcp, vaultosd"
echo "  desktop   $desktop_file"

if [[ $enable_service == 1 ]]; then
  command -v systemctl >/dev/null 2>&1 || die "systemctl is not available; the service needs systemd"
  mkdir -p "$(dirname "$unit_file")"
  sed -e "s|@APP@|$prefix/vaultos-preview|g" "$repo/scripts/vaultos-preview-backend.service" > "$unit_file.tmp"
  chmod 644 "$unit_file.tmp"
  mv -f "$unit_file.tmp" "$unit_file"
  systemctl --user daemon-reload
  systemctl --user enable --now vaultos-preview-backend.service
  echo "  service   $unit_file (enabled)"
  echo "            It unlocks only if background access is on in Settings."
  echo "            Status: systemctl --user status vaultos-preview-backend.service"
else
  echo "  service   not installed (pass --enable-service for background access under systemd)"
fi
