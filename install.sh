#!/usr/bin/env bash
# install.sh — install the Data Diode Gateway on Raspberry Pi OS (Bookworm).
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"

echo "[1/9] apt packages"
apt-get update -qq
apt-get install -y -qq python3 nftables rsync openssh-client ca-certificates

echo "[2/9] dedicated unprivileged user"
id -u diode >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin diode
DIODE_UID=$(id -u diode)
DIODE_GID=$(id -g diode)
echo "    diode uid=${DIODE_UID} gid=${DIODE_GID}"

echo "[3/9] directories"
install -d -m 0755 -o root  -g root  /etc/diode
install -d -m 0755 -o root  -g root  /var/lib/diode
install -d -m 0700 -o diode -g diode /var/lib/diode/staging
install -d -m 0700 -o root  -g root  /var/lib/diode/quarantine
install -d -m 0700 -o root  -g root  /var/lib/diode/archive
install -d -m 0750 -o root  -g root  /var/log/diode
install -d -m 0755 -o root  -g root  /run/diode

echo "[4/9] controller"
install -m 0755 "$REPO/diode-controller.py" /usr/local/sbin/diode-controller.py

echo "[5/9] configuration"
if [ ! -f /etc/diode/diode.conf ]; then
    install -m 0600 -o root -g root "$REPO/diode.conf.example" /etc/diode/diode.conf
    sed -i "s/^uid       = 993$/uid       = ${DIODE_UID}/" /etc/diode/diode.conf
fi

echo "[6/9] HMAC key"
if [ ! -f /etc/diode/hmac.key ]; then
    openssl rand -hex 64 > /etc/diode/hmac.key
fi
chmod 600 /etc/diode/hmac.key
chown root:root /etc/diode/hmac.key

echo "[7/9] base nftables ruleset"
install -m 0644 -o root -g root "$REPO/nftables-diode.conf" /etc/nftables-diode.conf
nft delete table inet diode 2>/dev/null || true
nft -f /etc/nftables-diode.conf

echo "[8/9] systemd units"
install -m 0644 -o root -g root "$REPO/systemd/diode-safe.service" /etc/systemd/system/
install -m 0644 -o root -g root "$REPO/systemd/diode.service"      /etc/systemd/system/
install -m 0644 -o root -g root "$REPO/systemd/diode.timer"        /etc/systemd/system/
systemctl daemon-reload

echo "[9/9] lockdown services"
bash "$REPO/lockdown-services.sh"

cat <<EOF

================================================================
 Installation complete.

 Remaining manual steps:

   1. Create the SSH key for the LAN target (owned by 'diode'):
        sudo install -d -m 0755 -o root -g root /etc/diode
        sudo ssh-keygen -t ed25519 -N "" -f /etc/diode/id_diode_ed25519
        sudo chown diode:diode /etc/diode/id_diode_ed25519 /etc/diode/id_diode_ed25519.pub
        sudo chmod 600 /etc/diode/id_diode_ed25519

   2. Authorise that key on the LAN server (user 'diode'):
        append /etc/diode/id_diode_ed25519.pub to ~/.ssh/authorized_keys
        on 192.168.10.20

   3. Pin the LAN host key:
        sudo ssh-keyscan -t ed25519 192.168.10.20 > /etc/diode/known_hosts
        sudo chown diode:diode /etc/diode/known_hosts
        sudo chmod 600 /etc/diode/known_hosts

   4. Install the TLS CA for the feed:
        sudo cp <your-ca.pem> /etc/diode/ca.pem
        sudo chmod 0644 /etc/diode/ca.pem

   5. Edit /etc/diode/diode.conf (URLs, IPs, ports).

   6. On the feed/source server, sign the bundle:
        openssl dgst -sha256 -hmac "\$(cat /etc/diode/hmac.key)" \\
            -hex -out latest.tar.gz.hmac latest.tar.gz

   7. Enable the gateway:
        sudo systemctl enable --now diode-safe.service
        sudo systemctl enable --now diode.timer
        journalctl -u diode.service -f
================================================================
EOF