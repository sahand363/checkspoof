#!/usr/bin/env bash
# CheckSpoof installer / updater.
#   curl -fsSL https://raw.githubusercontent.com/sahand363/checkspoof/main/install.sh | sudo bash
set -Eeuo pipefail

REPO=sahand363/checkspoof
BIN=/usr/local/bin/checkspoof
MENU=/usr/local/bin/spoof
CONF_DIR=/etc/checkspoof
ENV_FILE=$CONF_DIR/checkspoof.env
SERVICE=/etc/systemd/system/checkspoof.service
DL="https://github.com/$REPO/releases/latest/download"

say(){ echo -e "\033[38;5;141m›\033[0m $*"; }
die(){ echo -e "\033[38;5;203m✗\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash"
command -v systemctl >/dev/null 2>&1 || die "systemd is required."

case "$(uname -m)" in
  x86_64|amd64) ASSET=checkspoof ;;
  aarch64|arm64) ASSET=checkspoof-arm64 ;;
  *) die "Unsupported CPU architecture: $(uname -m)" ;;
esac

need=()
command -v curl >/dev/null 2>&1 || need+=(curl)
command -v iptables >/dev/null 2>&1 || need+=(iptables)
command -v ip >/dev/null 2>&1 || need+=(iproute2)
command -v sha256sum >/dev/null 2>&1 || need+=(coreutils)
if ((${#need[@]})); then
  say "Installing ${need[*]}…"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "${need[@]/iproute2/iproute}"
  elif command -v yum >/dev/null 2>&1; then yum install -y -q "${need[@]/iproute2/iproute}"
  else die "Please install: ${need[*]}"; fi
fi

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
say "Downloading the latest release…"
curl -fsSL --retry 4 --retry-delay 2 "$DL/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "Could not reach GitHub releases."
curl -fL --retry 4 --retry-delay 2 --progress-bar "$DL/$ASSET" -o "$tmp/$ASSET" || die "Binary download failed."
curl -fsSL --retry 4 --retry-delay 2 "$DL/spoof-menu.sh" -o "$tmp/spoof-menu.sh" || die "Menu download failed."
(cd "$tmp" && grep -E " (\*)?($ASSET|spoof-menu\.sh)\$" SHA256SUMS | sha256sum -c --status -) || die "Checksum mismatch. Nothing was installed."

if [[ -x "$BIN" ]]; then cp -a "$BIN" "$BIN.prev"; fi
if [[ -f "$MENU" ]]; then cp -a "$MENU" "$MENU.prev"; fi
install -m 755 "$tmp/$ASSET" "$BIN"
install -m 755 "$tmp/spoof-menu.sh" "$MENU"

mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
grep -q '^CHECKSPOOF_PORT=' "$ENV_FILE" || echo "CHECKSPOOF_PORT=${CHECKSPOOF_PORT:-8085}" >> "$ENV_FILE"
grep -q '^CHECKSPOOF_ADMIN_KEY=' "$ENV_FILE" || echo "CHECKSPOOF_ADMIN_KEY=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')" >> "$ENV_FILE"
PORT=$(grep -m1 '^CHECKSPOOF_PORT=' "$ENV_FILE" | cut -d= -f2)

cat > "$SERVICE" <<UNIT
[Unit]
Description=CheckSpoof source-address spoofing test
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$BIN -port \${CHECKSPOOF_PORT}
RuntimeDirectory=checkspoof
KillSignal=SIGTERM
TimeoutStopSec=15
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT/tcp" >/dev/null && say "ufw: allowed $PORT/tcp (panel)"
  ufw allow 5555/udp >/dev/null && say "ufw: allowed 5555/udp (test packets)"
fi

systemctl daemon-reload
systemctl enable checkspoof >/dev/null 2>&1
systemctl restart checkspoof
sleep 2

if [[ -r /dev/tty ]] && { : </dev/tty; } 2>/dev/null; then
  INSTALLED_NOW=1 exec "$MENU" </dev/tty
fi
echo
echo "CheckSpoof v$($BIN -version) is running."
echo "Panel: $("$MENU" link)"
echo "Open the menu anytime with: sudo spoof"
