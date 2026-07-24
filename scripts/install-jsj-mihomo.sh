#!/bin/sh
set -eu

repo="${MIHOMO_REPO:-JSJ-Experiments/mihomo}"
tag="${MIHOMO_RELEASE_TAG:-Prerelease-Alpha}"
base_url="${MIHOMO_BASE_URL:-}"
install_path="${MIHOMO_INSTALL_PATH:-/usr/local/bin/mihomo}"
service="${MIHOMO_SERVICE:-mihomo}"
rollback=false

usage() {
  cat <<USAGE
Usage: $0 [--install-path PATH] [--service NAME] [--rollback]

Environment overrides:
  MIHOMO_REPO         GitHub owner/repository (default: JSJ-Experiments/mihomo)
  MIHOMO_RELEASE_TAG  Release tag (default: Prerelease-Alpha)
  MIHOMO_BASE_URL     Direct directory URL containing the assets
  MIHOMO_INSTALL_PATH Binary destination (default: /usr/local/bin/mihomo)
  MIHOMO_SERVICE      systemd service to restart (default: mihomo)
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-path) install_path="$2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --rollback) rollback=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

restart_if_running() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$service"; then
    systemctl restart "$service"
  fi
}

backup_path="${install_path}.bak"
if [ "$rollback" = true ]; then
  if [ ! -f "$backup_path" ]; then
    echo "No backup found at $backup_path" >&2
    exit 1
  fi
  cp -f "$backup_path" "${install_path}.new"
  chmod 0755 "${install_path}.new"
  mv -f "${install_path}.new" "$install_path"
  restart_if_running
  "$install_path" -v
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) target="linux-amd64" ;;
  aarch64|arm64) target="linux-arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$base_url" ]; then
  base_url="https://github.com/${repo}/releases/download/${tag}"
fi
base_url="${base_url%/}"
asset="mihomo-${target}.gz"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$1" "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$1" "$2"
  else
    echo "curl or wget is required" >&2
    return 1
  fi
}

fetch "$tmpdir/checksums.txt" "$base_url/checksums.txt"
fetch "$tmpdir/$asset" "$base_url/$asset"
expected="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset {print $1; exit}' "$tmpdir/checksums.txt")"
actual="$(sha256sum "$tmpdir/$asset" | awk '{print $1}')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "SHA-256 verification failed (expected ${expected:-missing}, got $actual)" >&2
  exit 1
fi

gzip -dc "$tmpdir/$asset" > "$tmpdir/mihomo"
chmod 0755 "$tmpdir/mihomo"
"$tmpdir/mihomo" -v

install_dir="$(dirname "$install_path")"
mkdir -p "$install_dir"
if [ -f "$install_path" ]; then
  cp -f "$install_path" "$backup_path"
fi
cp -f "$tmpdir/mihomo" "${install_path}.new"
chmod 0755 "${install_path}.new"
mv -f "${install_path}.new" "$install_path"

if ! restart_if_running; then
  echo "Service restart failed; restoring $backup_path" >&2
  if [ -f "$backup_path" ]; then
    cp -f "$backup_path" "$install_path"
    chmod 0755 "$install_path"
    restart_if_running || true
  fi
  exit 1
fi

echo "Installed $asset to $install_path"
"$install_path" -v
