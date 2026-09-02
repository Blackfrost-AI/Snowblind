#!/usr/bin/env bash
# install.sh — set up ghost on a Debian/Kali-family host
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] re-running with sudo"
  exec sudo "$0" "$@"
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "[*] installing apt dependencies"
apt-get update
# conntrack: required for `conntrack -F` in killswitch (re-evaluates pre-existing flows)
# dnsutils:  provides `dig`, used by leaktest's real DNS-leak check
# Bridges (obfs4proxy / snowflake / meek) are not wired by default — install
# on demand with `sudo apt install -y obfs4proxy` and add a Bridge block to
# /etc/tor/torrc.ghost via the modules/tor.py:write_config edit.
apt-get install -y tor torsocks macchanger iptables curl jq python3 conntrack dnsutils

echo "[*] making ghost.py executable"
chmod +x "$ROOT/ghost.py"

echo "[*] symlinking /usr/local/bin/ghost -> $ROOT/ghost.py"
ln -sf "$ROOT/ghost.py" /usr/local/bin/ghost

echo "[*] disabling the system tor service (ghost runs its own instance)"
systemctl disable --now tor 2>/dev/null || true

echo "[*] dropping tmpfiles entry so /run/tor survives reboot (system tor is disabled, so its RuntimeDirectory won't fire)"
cat > /etc/tmpfiles.d/ghost-tor.conf <<'EOF'
d /run/tor 0750 debian-tor debian-tor -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/ghost-tor.conf

echo "[+] install complete. try: sudo ghost status"
