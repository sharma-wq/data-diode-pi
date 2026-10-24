#!/usr/bin/env bash
# lockdown-services.sh — reduce attack surface on the data diode.
set -euo pipefail

echo "[lockdown] disabling unnecessary services"
for svc in bluetooth hciuart avahi-daemon cups cups-browsed triggerhappy \
           ModemManager wpa_supplicant dphys-swapfile \
           serial-getty@ttyAMA0 serial-getty@ttyS0 systemd-timesyncd; do
    if systemctl list-unit-files --type=service 2>/dev/null \
            | grep -q "^${svc}.service"; then
        systemctl disable --now "$svc.service" >/dev/null 2>&1 || true
        echo "    disabled: $svc.service"
    fi
done

echo "[lockdown] applying kernel hardening sysctls"
cat > /etc/sysctl.d/99-diode.conf <<'EOF'
net.ipv4.ip_forward                 = 0
net.ipv6.conf.all.forwarding        = 0
net.ipv4.conf.all.accept_redirects  = 0
net.ipv4.conf.all.send_redirects    = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter         = 1
net.ipv4.tcp_syncookies             = 1
kernel.dmesg_restrict               = 1
kernel.kptr_restrict                = 2
kernel.yama.ptrace_scope            = 1
EOF
sysctl --system >/dev/null
echo "[lockdown] done"