#!/usr/bin/env bash
# CheckSpoof SSH control menu. Installed as /usr/local/bin/spoof.
#   sudo spoof            open the menu
#   sudo spoof update     update to the latest release
#   sudo spoof rollback   go back to the previous version
#   sudo spoof link       print the panel link
set -Eeuo pipefail

APP=checkspoof
REPO=sahand363/checkspoof
BIN=/usr/local/bin/checkspoof
MENU=/usr/local/bin/spoof
CONF_DIR=/etc/checkspoof
ENV_FILE=$CONF_DIR/checkspoof.env
SERVICE=/etc/systemd/system/checkspoof.service
RUN_DIR=/run/checkspoof

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) BIN_ASSET="checkspoof" ;;
  aarch64|arm64) BIN_ASSET="checkspoof-arm64" ;;
  *) echo "Unsupported CPU architecture: $ARCH" >&2; exit 1 ;;
esac
DL="https://github.com/$REPO/releases/latest/download"

if [[ -t 1 ]]; then
  B=$'\033[1m'; D=$'\033[2m'; A=$'\033[38;5;141m'; G=$'\033[38;5;114m'
  R=$'\033[38;5;203m'; Y=$'\033[38;5;221m'; N=$'\033[0m'
else
  B=; D=; A=; G=; R=; Y=; N=
fi

[[ $EUID -eq 0 ]] || { echo "Run: sudo spoof"; exit 1; }

ok(){   echo "  ${G}✓${N} $*"; }
warn(){ echo "  ${Y}!${N} $*"; }
err(){  echo "  ${R}✗${N} $*"; }
step(){ echo "  ${A}›${N} $*"; }
pause(){ echo; read -rp "  ${D}Press Enter to go back${N} " _ </dev/tty || true; }

getv(){ grep -m1 "^$1=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true; }
setv(){
  local k="$1" v="$2" tmp
  mkdir -p "$CONF_DIR"; touch "$ENV_FILE"
  tmp=$(mktemp)
  grep -v "^$k=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  install -m 600 "$tmp" "$ENV_FILE"; rm -f "$tmp"
}
new_key(){ head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Version of a binary. Releases before the menu existed reject -version
# and exit without starting a server, so this is always safe to call.
version_of(){
  local v
  v=$(timeout 3 "$1" -version 2>/dev/null | head -n1 || true)
  [[ "$v" =~ ^[0-9A-Za-z.\-]+$ ]] && echo "$v" || echo "?"
}

panel_port(){
  local p=""
  [[ -s "$RUN_DIR/port" ]] && p=$(tr -dc '0-9' < "$RUN_DIR/port")
  [[ -n "$p" ]] || p=$(getv CHECKSPOOF_PORT)
  echo "${p:-8085}"
}

public_ip(){
  local ip
  ip=$(getv PUBLIC_IP)
  if [[ -z "$ip" && -s "$RUN_DIR/public_ip" ]]; then ip=$(cat "$RUN_DIR/public_ip"); fi
  if [[ -z "$ip" ]]; then
    ip=$(curl -4fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || ip=""
    [[ -n "$ip" && -d "$RUN_DIR" ]] && echo "$ip" > "$RUN_DIR/public_ip"
  fi
  [[ -n "$ip" ]] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-SERVER-IP}"
}

panel_link(){ echo "https://$(public_ip):$(panel_port)/?key=$(getv CHECKSPOOF_ADMIN_KEY)"; }

svc_state(){ systemctl is-active "$APP" 2>/dev/null || true; }

health_ok(){
  local i code
  for i in $(seq 1 10); do
    sleep 1.5
    systemctl is-active --quiet "$APP" || continue
    code=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 3 "https://127.0.0.1:$(panel_port)/" || true)
    [[ "$code" =~ ^(200|401)$ ]] && return 0
  done
  return 1
}

header(){
  clear 2>/dev/null || true
  local st dot cur prev=""
  st=$(svc_state)
  case "$st" in active) dot="${G}● running${N}" ;; *) dot="${R}● ${st:-stopped}${N}" ;; esac
  cur=$(version_of "$BIN")
  [[ -x "$BIN.prev" ]] && prev="  ${D}(rollback: v$(version_of "$BIN.prev"))${N}"
  echo
  echo "  ${A}${B}◆ CheckSpoof${N}  ${D}v${N}${B}${cur}${N}${prev}   ${dot}"
  echo "  ${D}─────────────────────────────────────────────────────────────${N}"
  if [[ "${INSTALLED_NOW:-0}" == "1" ]]; then
    echo "  ${G}${B}Installed and running.${N}"
  fi
  echo "  ${D}Panel ${N}  ${A}$(panel_link)${N}"
  echo "  ${D}Menu  ${N}  ${B}sudo spoof${N}   ${D}·  update: ${N}sudo spoof update"
  echo "  ${D}─────────────────────────────────────────────────────────────${N}"
  echo
}

download_release(){
  # Downloads binary + menu into $1 and verifies both against SHA256SUMS.
  local tmp="$1"
  step "Downloading the latest release…"
  curl -fsSL --retry 4 --retry-delay 2 --connect-timeout 15 "$DL/SHA256SUMS" -o "$tmp/SHA256SUMS" \
    && curl -fL --retry 4 --retry-delay 2 --connect-timeout 15 --progress-bar "$DL/$BIN_ASSET" -o "$tmp/$BIN_ASSET" \
    && curl -fsSL --retry 4 --retry-delay 2 --connect-timeout 15 "$DL/spoof-menu.sh" -o "$tmp/spoof-menu.sh" \
    || { err "Download failed."; return 1; }
  if ! (cd "$tmp" && grep -E " (\*)?($BIN_ASSET|spoof-menu\.sh)\$" SHA256SUMS | sha256sum -c --status -); then
    err "Checksum mismatch. Nothing was installed."; return 1
  fi
  chmod +x "$tmp/$BIN_ASSET"
  ok "Downloaded v$(version_of "$tmp/$BIN_ASSET"), checksum verified."
}

update_app(){
  local tmp cur new
  tmp=$(mktemp -d)
  if ! download_release "$tmp"; then rm -rf "$tmp"; return 1; fi
  cur=$(version_of "$BIN"); new=$(version_of "$tmp/$BIN_ASSET")
  if [[ "$cur" == "$new" && "${1:-}" != "--force" ]]; then
    ok "Already on the latest version (v$cur)."
    rm -rf "$tmp"; return 0
  fi
  if [[ -x "$BIN" ]]; then
    cp -a "$BIN" "$BIN.prev"
    [[ -f "$MENU" ]] && cp -a "$MENU" "$MENU.prev"
    ok "Kept v$cur for rollback."
  fi
  install -m 755 "$tmp/$BIN_ASSET" "$BIN.tmp" && mv -f "$BIN.tmp" "$BIN"
  install -m 755 "$tmp/spoof-menu.sh" "$MENU.tmp" && mv -f "$MENU.tmp" "$MENU"
  rm -rf "$tmp"
  step "Restarting…"
  systemctl daemon-reload
  systemctl restart "$APP"
  if health_ok; then
    ok "CheckSpoof v$new is running."
    echo "  ${D}Panel${N}  ${A}$(panel_link)${N}"
    return 0
  fi
  err "The new version did not come up."
  journalctl -u "$APP" -n 20 --no-pager || true
  if [[ -x "$BIN.prev" ]]; then
    warn "Restoring the previous version…"
    rollback_app --yes || true
  fi
  return 1
}

rollback_app(){
  if [[ ! -x "$BIN.prev" ]]; then
    warn "No previous version saved yet. One is kept on every update."; return 1
  fi
  local cur prev
  cur=$(version_of "$BIN"); prev=$(version_of "$BIN.prev")
  if [[ "${1:-}" != "--yes" ]]; then
    read -rp "  Roll back from v$cur to v$prev? [y/N] " a </dev/tty
    [[ "$a" =~ ^[Yy]$ ]] || { echo "  Cancelled."; return 0; }
  fi
  mv -f "$BIN" "$BIN.swap" && mv -f "$BIN.prev" "$BIN" && mv -f "$BIN.swap" "$BIN.prev"
  if [[ -f "$MENU.prev" ]]; then
    mv -f "$MENU" "$MENU.swap" && mv -f "$MENU.prev" "$MENU" && mv -f "$MENU.swap" "$MENU.prev"
  fi
  systemctl restart "$APP"
  if health_ok; then
    ok "Rolled back to v$prev. Run update to move forward again."
  else
    err "v$prev is not answering either. Logs: journalctl -u $APP -n 50"; return 1
  fi
}

show_access(){
  local ip port key
  ip=$(public_ip); port=$(panel_port); key=$(getv CHECKSPOOF_ADMIN_KEY)
  echo "  ${B}Panel (HTTPS)${N}   ${A}https://$ip:$port/?key=$key${N}"
  echo "  ${B}Panel (HTTP)${N}    ${D}http://$ip:$port/?key=$key${N}"
  echo "  ${B}Admin key${N}       $key"
  echo "  ${B}UDP test port${N}   ${D}set per test in the panel (default 5555); open it on Server B${N}"
  echo
  echo "  ${D}The certificate is self-signed, so the browser shows a warning once.${N}"
  echo "  ${D}The pairing token is shown inside the panel.${N}"
}

open_fw(){
  # Opens a port in ufw when ufw is active. $1 = port/proto
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$1" >/dev/null && ok "ufw: allowed $1"
  fi
}

change_port(){
  local cur p
  cur=$(getv CHECKSPOOF_PORT); cur=${cur:-8085}
  read -rp "  New panel port [$cur]: " p </dev/tty
  p=${p:-$cur}
  [[ "$p" =~ ^[0-9]+$ && $p -ge 1 && $p -le 65535 ]] || { err "Invalid port."; return 1; }
  setv CHECKSPOOF_PORT "$p"
  open_fw "$p/tcp"
  systemctl restart "$APP"
  health_ok && ok "Panel now on port $(panel_port)." || err "Service did not come up. Check the logs."
}

reset_key(){
  read -rp "  Make a new admin key? The old link stops working. [y/N] " a </dev/tty
  [[ "$a" =~ ^[Yy]$ ]] || { echo "  Cancelled."; return 0; }
  setv CHECKSPOOF_ADMIN_KEY "$(new_key)"
  systemctl restart "$APP"
  health_ok && ok "New key active." || err "Service did not come up."
  echo "  ${D}Panel${N}  ${A}$(panel_link)${N}"
}

set_public_ip(){
  local cur ip
  cur=$(getv PUBLIC_IP)
  echo "  ${D}Only needed when auto-detection is wrong (e.g. behind NAT). Leave empty for auto.${N}"
  read -rp "  Public IPv4 [${cur:-auto}]: " ip </dev/tty
  if [[ -z "$ip" ]]; then
    sed -i '/^PUBLIC_IP=/d' "$ENV_FILE"
  elif [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    setv PUBLIC_IP "$ip"
  else
    err "Not an IPv4 address."; return 1
  fi
  rm -f "$RUN_DIR/public_ip"
  systemctl restart "$APP"
  health_ok && ok "Saved." || err "Service did not come up."
}

toggle_service(){
  if [[ "$(svc_state)" == "active" ]]; then
    systemctl stop "$APP" && ok "Stopped. Owned firewall chains were cleaned up."
  else
    systemctl start "$APP"
    health_ok && ok "Started." || err "Service did not come up."
  fi
}

cleanup_chains(){
  # Remove any CheckSpoof SNAT chains left behind (e.g. after a crash).
  command -v iptables >/dev/null 2>&1 || return 0
  local rule ch
  while read -r rule; do
    # shellcheck disable=SC2086
    [[ -n "$rule" ]] && iptables -t nat ${rule/-A /-D } 2>/dev/null || true
  done < <(iptables -t nat -S POSTROUTING 2>/dev/null | grep -- '-j CSPF_' || true)
  for ch in $(iptables -t nat -S 2>/dev/null | awk '$1=="-N" && $2 ~ /^CSPF_/ {print $2}'); do
    iptables -t nat -F "$ch" 2>/dev/null || true
    iptables -t nat -X "$ch" 2>/dev/null || true
  done
}

uninstall_app(){
  echo "  ${R}${B}This removes CheckSpoof, its service, settings and the menu.${N}"
  read -rp "  Type REMOVE to confirm: " c </dev/tty
  [[ "$c" == "REMOVE" ]] || { echo "  Cancelled."; return 0; }
  systemctl disable --now "$APP" 2>/dev/null || true
  cleanup_chains
  rm -f "$SERVICE" "$BIN" "$BIN.prev" "$MENU.prev" /tmp/checkspoof_snat_journal.json
  rm -rf "$CONF_DIR" "$RUN_DIR"
  systemctl daemon-reload
  rm -f "$MENU"
  ok "CheckSpoof was removed."
  exit 0
}

case "${1:-}" in
  update|--update)     update_app "${2:-}"; exit $? ;;
  rollback|--rollback) rollback_app; exit $? ;;
  link)                panel_link; exit 0 ;;
  version|-v)          version_of "$BIN"; exit 0 ;;
  uninstall)           uninstall_app ;;
  "") ;;
  *) echo "Usage: sudo spoof [update|rollback|link|version|uninstall]"; exit 1 ;;
esac

while true; do
  header
  INSTALLED_NOW=0
  if [[ "$(svc_state)" == "active" ]]; then toggle="Stop service"; else toggle="Start service"; fi
  cat <<EOF
  ${A}1${N}  Update to latest version
  ${A}2${N}  Roll back to previous version
  ${A}3${N}  Show panel link and admin key
  ${A}4${N}  Change panel port
  ${A}5${N}  Reset admin key
  ${A}6${N}  Set public IP manually
  ${A}7${N}  Restart service
  ${A}8${N}  $toggle
  ${A}9${N}  Live logs  ${D}(Ctrl+C to leave)${N}
  ${R}10${N} Uninstall
  ${D}0${N}  Exit
EOF
  echo
  read -rp "  Choose: " choice </dev/tty || exit 0
  echo
  case "$choice" in
    1) update_app || true; pause ;;
    2) rollback_app || true; pause ;;
    3) show_access; pause ;;
    4) change_port || true; pause ;;
    5) reset_key || true; pause ;;
    6) set_public_ip || true; pause ;;
    7) systemctl restart "$APP"; health_ok && ok "Restarted." || err "Service did not come up."; pause ;;
    8) toggle_service || true; pause ;;
    9) journalctl -u "$APP" -f -n 50 || true ;;
    10) uninstall_app ;;
    0|q|Q) exit 0 ;;
    *) ;;
  esac
done
