#!/usr/bin/env bash
# Install or remove a per-user LaunchAgent that runs `VaultOS --service`, the optional
# always-on VaultOS owner. Nothing runs this automatically.
#
# The service is the installed app's own program without its windows. It starts serving only
# after background access is on in the app's Settings, waits while a VaultOS window owns the
# vault, honours a manual lock, and stops (status 0, so launchd does not restart it) if
# background access is off or the remembered password no longer opens the vault.
set -euo pipefail

label="org.vaultos.preview.backend"
plist="$HOME/Library/LaunchAgents/$label.plist"
log_dir="$HOME/Library/Logs/VaultOS-Preview"
app="/Applications/VaultOS.app"
data_dir=""
sync_repo=""
mode="install"

usage() {
  cat <<EOF
Usage: $0 [--app PATH] [--data-dir DIR] [--sync-repo DIR] [--print]
       $0 --uninstall

  --app PATH       The installed VaultOS.app (default: /Applications/VaultOS.app)
  --data-dir DIR   Absolute VAULTOS_DATA_DIR, only if you use a nondefault one
  --sync-repo DIR  Absolute VAULTOS_SYNC_REPO, only if you use a nondefault one
  --print          Print the LaunchAgent property list without installing it
  --uninstall      Stop the service and remove its LaunchAgent
EOF
}

die() { echo "$*" >&2; exit 1; }

while (($#)); do
  case $1 in
    --uninstall) mode="uninstall" ;;
    --print) mode="print" ;;
    --app) app=${2:?--app needs a path}; shift ;;
    --data-dir) data_dir=${2:?--data-dir needs a directory}; shift ;;
    --sync-repo) sync_repo=${2:?--sync-repo needs a directory}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

[[ $(uname -s) == Darwin ]] || die "This installer is for macOS LaunchAgents."
domain="gui/$(id -u)"

if [[ $mode == uninstall ]]; then
  launchctl bootout "$domain/$label" 2>/dev/null || true
  rm -f "$plist"
  echo "Removed $label. Vault data, Keychain items and logs were not touched."
  exit 0
fi

app="${app%/}"
[[ $app == /* ]] || die "--app must be an absolute path: $app"
program="$app/Contents/MacOS/VaultOS"
[[ -x $program && -x $app/Contents/Helpers/vaultosd ]] \
  || die "$app is not a VaultOS 0.3 app (no Contents/MacOS/VaultOS and Contents/Helpers/vaultosd). Pass --app."
for dir in "$data_dir" "$sync_repo"; do
  [[ -z $dir || $dir == /* ]] || die "Directories must be absolute: $dir"
done

xml() {
  local amp='&amp;' lt='&lt;' gt='&gt;' s=$1
  s=${s//&/"$amp"}
  s=${s//</"$lt"}
  s=${s//>/"$gt"}
  printf '%s' "$s"
}

env_entry() { printf '    <key>%s</key><string>%s</string>\n' "$1" "$(xml "$2")"; }

render() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>
    <string>$(xml "$program")</string><string>--service</string>
  </array>
  <key>EnvironmentVariables</key><dict>
$(env_entry PATH "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
$([[ -n $data_dir ]] && env_entry VAULTOS_DATA_DIR "$data_dir")
$([[ -n $sync_repo ]] && env_entry VAULTOS_SYNC_REPO "$sync_repo")
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>$(xml "$log_dir/backend.log")</string>
</dict></plist>
EOF
}

if [[ $mode == print ]]; then
  render
  exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents"
mkdir -p -m 700 "$log_dir"
tmp="$(mktemp "$plist.XXXXXX")"
render >"$tmp"
plutil -lint -s "$tmp" || { rm -f "$tmp"; die "Generated property list is invalid."; }
chmod 644 "$tmp"
mv "$tmp" "$plist"
launchctl bootout "$domain/$label" 2>/dev/null || true
launchctl bootstrap "$domain" "$plist"
echo "Installed $label."
echo "It serves only while background access is on and no VaultOS window owns the vault."
echo "Log: $log_dir/backend.log   Remove: $0 --uninstall"
