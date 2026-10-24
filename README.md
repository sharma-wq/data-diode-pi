FILE: data-diode-pi/README.md

markdown
# Data Diode Gateway for Raspberry Pi

Fail-closed, one-way, offline (store-and-forward) gateway that pulls data
from an untrusted Internet feed, verifies its HMAC, and pushes it onto a
protected LAN — with a per-application nftables allow-list and mutual
exclusion of the two NICs.

## Layout
data-diode-pi/
├── README.md
├── diode-controller.py # single-file controller (root, FSM)
├── nftables-diode.conf # base lockdown ruleset (default DROP)
├── diode.conf.example # config template (/etc/diode/diode.conf)
├── install.sh # installer
├── lockdown-services.sh # disable attack-surface services + sysctl
├── systemd/
│ ├── diode-safe.service # boot-time fail-closed lockdown
│ ├── diode.service # one cycle per trigger
│ └── diode.timer # periodic trigger
└── tests/
└── acceptance.sh # invariant smoke tests

text

## How the diode works

1. `diode-safe.service` runs at boot, brings **both** NICs down, and loads
   the base `nftables-diode.conf` (default DROP on in/out/forward).
2. `diode.timer` fires `diode.service` every 5 minutes.
3. `diode.service` runs `diode-controller.py --once`, which:
   - `ISOLATE`s both NICs,
   - enables only the `diode-fetch` firewall app, brings `eth0` UP,
     downloads `latest.tar.gz` + `latest.tar.gz.hmac` **as the unprivileged
     `diode` user**,
   - drops `eth0`, empties the firewall,
   - verifies HMAC-SHA256 with **both NICs DOWN**,
   - safe-extracts the archive (rejects `..`, absolute paths, non-regular
     members, disallowed extensions),
   - enables only the `diode-push` firewall app, brings `eth1` UP,
     rsyncs to the LAN server **as the unprivileged `diode` user**,
   - drops `eth1`, empties the firewall, archives the bundle, goes `IDLE`.
4. Any fault ⇒ `ISOLATED` (both NICs down, firewall flushed).
5. `systemd` `ExecStopPost` re-applies the base ruleset on crash / kill.

## Security properties

- At most one of `eth0`/`eth1` administratively UP at any instant.
- No firewall accept rules exist at rest.
- `policy drop` on `input`, `output`, `forward`.
- `net.ipv4.ip_forward=0`, IPv6 disabled on both NICs.
- Network helpers run as unprivileged user `diode` (uid/gid from `pwd`).
- HMAC key is `root:root` `0600` and never readable by `diode`.
- TLS 1.2+ only, CA pinned, redirects limited to HTTPS.
- SSH host key pinned (`StrictHostKeyChecking=yes`), password auth off,
  `BatchMode=yes`.
- systemd sandbox: `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectKernelModules`, `RestrictAddressFamilies`,
  `SystemCallFilter=@system-service @network-io`, minimal
  `CapabilityBoundingSet`.
- Controller is a singleton (`flock` on `/run/diode/diode.lock`).

## Install

```bash
sudo ./install.sh
# follow the printed checklist (SSH key, TLS CA, HMAC key on feed server)
sudo systemctl enable --now diode-safe.service diode.timer
journalctl -u diode.service -f
Manually run a single cycle
bash
sudo /usr/local/sbin/diode-controller.py --config /etc/diode/diode.conf --once
Sign the bundle (on the feed/source server)
bash
openssl dgst -sha256 -hmac "$(cat /etc/diode/hmac.key)" \
    -hex -out latest.tar.gz.hmac latest.tar.gz
VS Code extensions
ms-python.python

redhat.vscode-yaml

timonwong.shellcheck

bierner.markdown-mermaid

text

FILE: data-diode-pi/diode-controller.py

```python
#!/usr/bin/env python3
"""
diode-controller.py — single-file Data Diode Gateway controller for Raspberry Pi.

Invariants enforced by this process:
  * At most one of WAN/LAN interfaces is administratively UP at any instant.
  * nftables table `inet diode` has policy DROP on input/output/forward.
  * No application accept rules exist at rest.
  * Any exception or signal ⇒ both NICs DOWN + base ruleset reloaded.
  * Network helpers run as unprivileged user 'diode' (uid/gid from pwd).
"""

import argparse
import configparser
import fcntl
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import pwd
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

LOG = logging.getLogger("diode")
STOP = False


# ============================================================================
# Configuration
# ============================================================================
class Config:
    def __init__(self, cp):
        self.cp = cp
        self.diode = dict(cp["diode"])
        self.fetch = dict(cp["fetch"])
        self.push = dict(cp["push"])
        self.apps = {}
        for sec in cp.sections():
            if sec.startswith("firewall."):
                self.apps[sec[len("firewall."):]] = dict(cp[sec])

    @classmethod
    def load(cls, path):
        cp = configparser.ConfigParser()
        if not cp.read(path):
            raise FileNotFoundError(path)
        for req in ("diode", "fetch", "push"):
            if not cp.has_section(req):
                raise ValueError(f"missing section [{req}] in {path}")
        cfg = cls(cp)
        if cfg.diode["wan_iface"] == cfg.diode["lan_iface"]:
            raise ValueError("wan_iface and lan_iface must differ")
        kp = cfg.diode["hmac_key_file"]
        st = os.stat(kp)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(f"{kp} must be mode 0600 or stricter")
        if st.st_size < 32:
            raise ValueError("HMAC key too short (< 32 bytes)")
        return cfg


# ============================================================================
# Logging
# ============================================================================
def setup_logging(log_dir, name="diode"):
    os.makedirs(log_dir, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S"
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)

    fh = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, f"{name}.log"),
        maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8",
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    try:
        sl = logging.handlers.SysLogHandler(address="/dev/log")
        sl.setFormatter(fmt)
        root.addHandler(sl)
    except Exception:
        pass


# ============================================================================
# Signals
# ============================================================================
def _on_signal(signum, _frame):
    global STOP
    STOP = True
    LOG.warning("signal %s received, shutting down", signum)


# ============================================================================
# Interface management
# ============================================================================
def _sanitize_iface(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 15:
        raise ValueError("invalid interface name")
    if not all(c.isalnum() or c in "-_." for c in name):
        raise ValueError("invalid character in interface name")
    return name


def _run(argv, timeout=15):
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, check=False, shell=False)
        if r.returncode != 0:
            LOG.error("cmd failed rc=%s %s :: %s",
                      r.returncode, argv, r.stderr.strip())
        return r.returncode == 0
    except Exception:
        LOG.exception("cmd exception %s", argv)
        return False


def iface_up(iface):
    return _run(["ip", "link", "set", "dev", _sanitize_iface(iface), "up"])


def iface_down(iface):
    return _run(["ip", "link", "set", "dev", _sanitize_iface(iface), "down"])


def harden_iface(iface):
    iface = _sanitize_iface(iface)
    _run(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"])
    _run(["sysctl", "-w", f"net.ipv4.conf.{iface}.send_redirects=0"])
    _run(["sysctl", "-w", f"net.ipv4.conf.{iface}.accept_redirects=0"])
    _run(["sysctl", "-w", f"net.ipv4.conf.{iface}.accept_source_route=0"])


def isolate_all(ifaces):
    ok = True
    for i in ifaces:
        ok = iface_down(i) and ok
    return ok


# ============================================================================
# Firewall (nftables)
# ============================================================================
FAMILY = "inet"
TABLE = "diode"


class FirewallManager:
    def __init__(self, cfg):
        self.apps = cfg.apps

    def _q(self, s):
        return '"' + str(s).replace('"', '') + '"'

    def _match(self, app):
        parts = []
        if app.get("iface"):
            key = "iif" if app.get("direction", "input") == "input" else "oif"
            parts.append(f"{key} {self._q(app['iface'])}")
        proto = app.get("proto")
        if proto == "tcp":
            parts.append("ip protocol tcp")
            if app.get("dport"):
                parts.append(f"tcp dport {int(app['dport'])}")
        elif proto == "udp":
            parts.append("ip protocol udp")
            if app.get("dport"):
                parts.append(f"udp dport {int(app['dport'])}")
        if app.get("direction", "input") == "output":
            if app.get("uid") is not None:
                parts.append(f"meta skuid {int(app['uid'])}")
            if app.get("dst"):
                parts.append(f"ip daddr {app['dst']}")
        else:
            if app.get("src"):
                parts.append(f"ip saddr {app['src']}")
        return " ".join(parts)

    def _render(self, enabled):
        L = [f"table {FAMILY} {TABLE} {{"]
        L.append("  chain input {")
        L.append("    type filter hook input priority 0; policy drop;")
        L.append('    iif "lo" accept')
        L.append("    ct state established,related accept")
        L.append("    ct state invalid drop")
        for name in sorted(enabled):
            a = self.apps.get(name)
            if a and a.get("direction", "input") == "input":
                L.append(f"    {self._match(a)} ct state new counter accept")
        L.append("  }")
        L.append("  chain output {")
        L.append("    type filter hook output priority 0; policy drop;")
        L.append('    oif "lo" accept')
        L.append("    ct state established,related accept")
        for name in sorted(enabled):
            a = self.apps.get(name)
            if a and a.get("direction") == "output":
                L.append(f"    {self._match(a)} ct state new counter accept")
        L.append("  }")
        L.append("  chain forward {")
        L.append("    type filter hook forward priority 0; policy drop;")
        L.append("  }")
        L.append("}")
        return "\n".join(L) + "\n"

    def apply(self, enabled):
        text = self._render(enabled)
        r = subprocess.run(["nft", "-f", "-"], input=text,
                           capture_output=True, text=True, timeout=15,
                           shell=False, check=False)
        if r.returncode != 0:
            LOG.error("nft load failed: %s", r.stderr.strip())
            return False
        return True

    def enable(self, name):
        if name not in self.apps:
            raise KeyError(f"unknown application '{name}'")
        ok = self.apply({name})
        LOG.info("firewall: enable app=%s ok=%s", name, ok)
        return ok

    def disable_all(self):
        ok = self.apply(set())
        LOG.info("firewall: disable all ok=%s", ok)
        return ok

    def panic(self):
        # Best-effort reload of default-drop ruleset with no applications.
        self.apply(set())


# ============================================================================
# Integrity
# ============================================================================
class Integrity:
    def __init__(self, d):
        self.key_file = d["hmac_key_file"]
        self.quarantine_dir = d["quarantine_dir"]
        self.archive_dir = d["archive_dir"]
        self.max_bytes = int(d["max_file_size_mb"]) * 1024 * 1024
        self.allowed_ext = {e.strip().lower()
                            for e in d["allowed_extensions"].split(",")
                            if e.strip()}

    def _key(self):
        with open(self.key_file, "rb") as f:
            k = f.read().strip()
        if len(k) < 32:
            raise ValueError("HMAC key too short")
        return k

    def verify(self, bundle_path):
        if not os.path.isfile(bundle_path):
            raise FileNotFoundError(bundle_path)
        if os.path.getsize(bundle_path) > self.max_bytes:
            raise ValueError("bundle exceeds max_file_size_mb")
        hmac_path = bundle_path + ".hmac"
        with open(hmac_path, "rb") as f:
            expected = f.read().strip()
        h = hmac.new(self._key(), digestmod=hashlib.sha256)
        with open(bundle_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        actual = h.hexdigest().encode()
        if not hmac.compare_digest(expected.lower(), actual.lower()):
            raise ValueError("HMAC verification failed")
        LOG.info("integrity OK: %s", os.path.basename(bundle_path))

    def safe_extract(self, bundle_path, dest_dir):
        os.makedirs(dest_dir, exist_ok=True)
        base = os.path.realpath(dest_dir)
        with tarfile.open(bundle_path, "r:*") as tf:
            for m in tf.getmembers():
                if m.name.startswith("/") or ".." in m.name.split("/"):
                    raise ValueError(f"unsafe path in archive: {m.name}")
                if not (m.isfile() or m.isdir()):
                    raise ValueError(f"unsupported member type: {m.name}")
                ext = os.path.splitext(m.name)[1].lower()
                if ext and ext not in self.allowed_ext:
                    raise ValueError(f"disallowed extension: {m.name}")
                target = os.path.realpath(os.path.join(base, m.name))
                if not target.startswith(base + os.sep) and target != base:
                    raise ValueError(f"path escape: {m.name}")
            tf.extractall(base)

    def quarantine(self, path):
        os.makedirs(self.quarantine_dir, exist_ok=True)
        for p in (path, path + ".hmac"):
            if os.path.exists(p):
                shutil.move(p, os.path.join(self.quarantine_dir,
                                            os.path.basename(p)))

    def archive(self, path):
        os.makedirs(self.archive_dir, exist_ok=True)
        for p in (path, path + ".hmac"):
            if os.path.exists(p):
                shutil.move(p, os.path.join(self.archive_dir,
                                            os.path.basename(p)))


# ============================================================================
# Privilege drop helper
# ============================================================================
def run_as(argv, uid, gid, timeout, stdin_data=None):
    """Run argv as (uid, gid) with empty supplementary groups."""
    return subprocess.run(
        argv, input=stdin_data, capture_output=True, text=True,
        timeout=timeout, shell=False, check=False,
        user=uid, group=gid, extra_groups=[],
    )


# ============================================================================
# Fetch worker (runs as unprivileged user)
# ============================================================================
def fetch_worker(url, dest, ca, timeout, max_bytes, max_redirects):
    if not url.lower().startswith("https://"):
        raise ValueError("only https:// URLs are allowed")

    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    class _LimitedRedirect(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            self.count = 0

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self.count += 1
            if self.count > max_redirects:
                raise urllib.error.HTTPError(
                    newurl, code, "too many redirects", headers, fp)
            if not newurl.lower().startswith("https://"):
                raise urllib.error.HTTPError(
                    newurl, code, "insecure redirect", headers, fp)
            return super().redirect_request(
                req, fp, code, msg, headers, newurl)

    def _dl(u, d, limit):
        opener = urllib.request.build_opener(
            _LimitedRedirect(),
            urllib.request.HTTPSHandler(context=ctx),
        )
        req = urllib.request.Request(u, headers={"User-Agent": "diode/1.0"})
        written = 0
        tmp = d + ".part"
        with opener.open(req, timeout=timeout) as r:
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status}")
            with open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        raise ValueError("download exceeds size limit")
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
        os.replace(tmp, d)
        return written

    _dl(url, dest, max_bytes)
    _dl(url + ".hmac", dest + ".hmac", 8192)
    print(f"OK {dest}")


# ============================================================================
# Push worker (runs as unprivileged user)
# ============================================================================
def push_worker(src, host, user, path, key, known_hosts, timeout):
    if not os.path.isdir(src):
        raise NotADirectoryError(src)
    for f in (key, known_hosts):
        if not os.path.isfile(f):
            raise FileNotFoundError(f)

    ssh = (
        f"ssh -i {key} -o IdentitiesOnly=yes -o BatchMode=yes "
        f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts} "
        f"-o ConnectTimeout={timeout} -o PubkeyAuthentication=yes "
        f"-o PasswordAuthentication=no -o PreferredAuthentications=publickey"
    )
    cmd = [
        "rsync", "-a", "--protect-args", "--no-owner", "--no-group",
        "--chmod=D700,F600", "-e", ssh,
        src + "/", f"{user}@{host}:{path}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       timeout=timeout + 60, shell=False, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"rsync rc={r.returncode}: {r.stderr.strip()}")
    print("OK")


# ============================================================================
# Controller
# ============================================================================
class Controller:
    def __init__(self, cfg):
        self.cfg = cfg
        d = cfg.diode
        self.wan = d["wan_iface"]
        self.lan = d["lan_iface"]
        self.staging = d["staging_dir"]
        self.state_file = d["state_file"]
        self.lock_file = d["lock_file"]
        self.user = d["run_as_user"]
        self.interval = int(d.get("cycle_interval_s", "60"))
        self.fw = FirewallManager(cfg)
        self.integ = Integrity(d)
        self._fh = None
        pw = pwd.getpwnam(self.user)
        self.uid = pw.pw_uid
        self.gid = pw.pw_gid

    def _lock(self):
        os.makedirs(os.path.dirname(self.lock_file), exist_ok=True)
        self._fh = open(self.lock_file, "w")
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            LOG.error("another controller instance is running")
            sys.exit(1)

    def _state(self, name, **extra):
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        doc = {"state": name,
               "ts": datetime.now(timezone.utc).isoformat(),
               **extra}
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_file)
        LOG.info("STATE=%s %s", name, extra if extra else "")

    def isolate(self, reason):
        LOG.warning("ISOLATE: %s", reason)
        isolate_all([self.wan, self.lan])
        self.fw.panic()
        self._state("ISOLATED", reason=str(reason)[:300])

    def cycle(self):
        d = self.cfg.diode
        self.isolate("cycle-start")

        # ---------- STAGE 1: WAN FETCH ----------
        LOG.info("STAGE 1/3 WAN FETCH on %s", self.wan)
        harden_iface(self.wan)
        if not self.fw.enable("diode-fetch"):
            self.isolate("firewall-enable-fetch-failed")
            return
        if not iface_up(self.wan):
            self.isolate("wan-up-failed")
            return
        self._state("WAN_UP")

        bundle = os.path.join(self.staging, "latest.tar.gz")
        try:
            r = run_as(
                [sys.executable, os.path.abspath(__file__),
                 "--fetch-worker",
                 "--url", self.cfg.fetch["url"],
                 "--dest", bundle,
                 "--ca", self.cfg.fetch["tls_ca"],
                 "--timeout", self.cfg.fetch["timeout_s"],
                 "--max-bytes", str(int(d["max_file_size_mb"]) * 1024 * 1024),
                 "--max-redirects", self.cfg.fetch.get("max_redirects", "2")],
                uid=self.uid, gid=self.gid,
                timeout=int(self.cfg.fetch["timeout_s"]) + 60,
            )
            if r.returncode != 0:
                raise RuntimeError(
                    f"fetch rc={r.returncode}: {r.stderr[-300:]}")
        except Exception as e:
            self.isolate(f"fetch-failed: {e}")
            return
        finally:
            iface_down(self.wan)
            self.fw.disable_all()
            self._state("WAN_DOWN")

        # ---------- STAGE 2: VERIFY ----------
        LOG.info("STAGE 2/3 VERIFY (both NICs down)")
        try:
            self.integ.verify(bundle)
        except Exception as e:
            self.integ.quarantine(bundle)
            self.isolate(f"integrity-failed: {e}")
            return

        payload = os.path.join(self.staging, "payload")
        try:
            self.integ.safe_extract(bundle, payload)
        except Exception as e:
            self.integ.quarantine(bundle)
            self.isolate(f"extract-failed: {e}")
            return

        # ---------- STAGE 3: LAN PUSH ----------
        LOG.info("STAGE 3/3 LAN PUSH on %s", self.lan)
        harden_iface(self.lan)
        if not self.fw.enable("diode-push"):
            self.isolate("firewall-enable-push-failed")
            return
        if not iface_up(self.lan):
            self.isolate("lan-up-failed")
            return
        self._state("LAN_UP")

        p = self.cfg.push
        try:
            r = run_as(
                [sys.executable, os.path.abspath(__file__),
                 "--push-worker",
                 "--src", payload,
                 "--host", p["target_host"],
                 "--user", p["target_user"],
                 "--path", p["target_path"],
                 "--key", p["ssh_key"],
                 "--known-hosts", p["known_hosts"],
                 "--timeout", p["connect_timeout_s"]],
                uid=self.uid, gid=self.gid,
                timeout=int(p["connect_timeout_s"]) + 120,
            )
            if r.returncode != 0:
                raise RuntimeError(
                    f"push rc={r.returncode}: {r.stderr[-300:]}")
        except Exception as e:
            self.isolate(f"push-failed: {e}")
            return
        finally:
            iface_down(self.lan)
            self.fw.disable_all()
            self._state("LAN_DOWN")

        self.integ.archive(bundle)
        self._state("IDLE")

    def run(self, once=False):
        LOG.info("controller start wan=%s lan=%s user=%s once=%s",
                 self.wan, self.lan, self.user, once)
        try:
            while not STOP:
                try:
                    self.cycle()
                except Exception:
                    LOG.exception("cycle crashed -> isolating")
                    self.isolate("cycle-crash")
                if once:
                    break
                for _ in range(self.interval):
                    if STOP:
                        break
                    time.sleep(1)
        finally:
            self.isolate("shutdown")
            LOG.info("controller stop")


# ============================================================================
# CLI
# ============================================================================
def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/diode/diode.conf")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--fetch-worker", action="store_true")
    ap.add_argument("--push-worker", action="store_true")
    ap.add_argument("--url")
    ap.add_argument("--dest")
    ap.add_argument("--ca")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--max-bytes", type=int, default=4096 * 1024 * 1024)
    ap.add_argument("--max-redirects", type=int, default=2)
    ap.add_argument("--src")
    ap.add_argument("--host")
    ap.add_argument("--user")
    ap.add_argument("--path")
    ap.add_argument("--key")
    ap.add_argument("--known-hosts")
    return ap.parse_args()


def main():
    args = parse_args()

    if args.fetch_worker:
        try:
            fetch_worker(args.url, args.dest, args.ca, args.timeout,
                         args.max_bytes, args.max_redirects)
            return 0
        except Exception as e:
            print(f"ERR {e}", file=sys.stderr)
            return 1

    if args.push_worker:
        try:
            push_worker(args.src, args.host, args.user, args.path,
                        args.key, args.known_hosts, args.timeout)
            return 0
        except Exception as e:
            print(f"ERR {e}", file=sys.stderr)
            return 1

    cfg = Config.load(args.config)
    setup_logging(cfg.diode["log_dir"], "controller")

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    ctl = Controller(cfg)
    ctl._lock()
    ctl.run(once=args.once)
    return 0


if __name__ == "__main__":
    sys.exit(main())
FILE: data-diode-pi/nftables-diode.conf

nft
# nftables-diode.conf — base lockdown ruleset for the data diode.
# Loaded at boot by diode-safe.service and by install.sh.
# The controller atomically replaces `table inet diode` whenever it
# enables/disables an application. Between cycles this file defines the
# resting state: default DROP on input/output/forward, loopback + conntrack
# established only.

table inet diode {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
    }

    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state established,related accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
FILE: data-diode-pi/diode.conf.example

ini
# ==========================================================================
# diode.conf — Data Diode Gateway configuration
# Copy to /etc/diode/diode.conf (mode 0600 root:root) and edit.
# ==========================================================================

[diode]
wan_iface          = eth0
lan_iface          = eth1
staging_dir        = /var/lib/diode/staging
quarantine_dir     = /var/lib/diode/quarantine
archive_dir        = /var/lib/diode/archive
state_file         = /var/lib/diode/state.json
lock_file          = /run/diode/diode.lock
hmac_key_file      = /etc/diode/hmac.key
log_dir            = /var/log/diode
max_file_size_mb   = 4096
allowed_extensions = .csv,.json,.xml,.txt,.gz,.tar,.tgz,.zip
run_as_user        = diode
cycle_interval_s   = 60

[fetch]
url           = https://updates.example.com/export/latest.tar.gz
tls_ca        = /etc/diode/ca.pem
timeout_s     = 300
max_redirects = 2

[push]
target_host       = 192.168.10.20
target_user       = diode
target_path       = /srv/incoming/
ssh_key           = /etc/diode/id_diode_ed25519
known_hosts       = /etc/diode/known_hosts
connect_timeout_s = 20

# ---- Per-application firewall (default DROP everywhere else) ------------
# Each [firewall.<name>] section describes one named application.
# install.sh will replace uid = 993 with the actual uid of the 'diode' user.

[firewall.diode-fetch]
iface     = eth0
direction = input
proto     = tcp
dport     = 443
# src = 203.0.113.0/24         ; optional source restriction

[firewall.diode-push]
iface     = eth1
direction = output
proto     = tcp
dport     = 22
dst       = 192.168.10.20
uid       = 993
FILE: data-diode-pi/install.sh

bash
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
FILE: data-diode-pi/lockdown-services.sh

bash
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
FILE: data-diode-pi/systemd/diode-safe.service

ini
[Unit]
Description=Data Diode — fail-closed boot lockdown
DefaultDependencies=no
After=local-fs.target
Before=diode.service diode.timer
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Bring both interfaces DOWN before anything else runs.
ExecStart=-/bin/sh -c 'ip link set dev eth0 down 2>/dev/null || true'
ExecStart=-/bin/sh -c 'ip link set dev eth1 down 2>/dev/null || true'

# Ensure default-drop ruleset is loaded (idempotent).
ExecStart=-/bin/sh -c 'nft delete table inet diode 2>/dev/null || true'
ExecStart=-/bin/sh -c 'nft -f /etc/nftables-diode.conf'

[Install]
WantedBy=multi-user.target
FILE: data-diode-pi/systemd/diode.service

ini
[Unit]
Description=Data Diode Gateway — one transfer cycle
After=diode-safe.service network.target
Requires=diode-safe.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/diode-controller.py --config /etc/diode/diode.conf --once
User=root
Group=root
TimeoutStartSec=3600

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/diode /var/log/diode /run/diode /etc/diode
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service @network-io
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID
UMask=0077

# Fail-closed: any stop / kill / crash forces both links down and
# re-applies a self-contained default-DROP ruleset (inline so that a
# missing /etc/nftables-diode.conf cannot leave the firewall open).
ExecStopPost=-/bin/sh -c 'ip link set dev eth0 down 2>/dev/null || true'
ExecStopPost=-/bin/sh -c 'ip link set dev eth1 down 2>/dev/null || true'
ExecStopPost=-/bin/sh -c 'nft delete table inet diode 2>/dev/null || true'
ExecStopPost=-/bin/sh -c 'nft -f /etc/nftables-diode.conf 2>/dev/null || { nft add table inet diode; nft add chain inet diode input  "{ type filter hook input  priority 0; policy drop; }"; nft add chain inet diode output "{ type filter hook output priority 0; policy drop; }"; nft add chain inet diode forward "{ type filter hook forward priority 0; policy drop; }"; }'

[Install]
WantedBy=multi-user.target
FILE: data-diode-pi/systemd/diode.timer

ini
[Unit]
Description=Data Diode Gateway — periodic cycle trigger

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=10s
Unit=diode.service
Persistent=false

[Install]
WantedBy=timers.target
FILE: data-diode-pi/tests/acceptance.sh

bash
#!/usr/bin/env bash
# tests/acceptance.sh — invariant smoke tests for the data diode.
# Run on an installed Pi:  sudo tests/acceptance.sh
set -uo pipefail

PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
ck()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

CTL=/usr/local/sbin/diode-controller.py
CFG=/etc/diode/diode.conf
NFTFILE=/etc/nftables-diode.conf
HMACKEY=/etc/diode/hmac.key

echo "== prerequisite checks =="
ck "controller present"                 "[ -x $CTL ]"
ck "config present"                     "[ -f $CFG ]"
ck "hmac key present"                   "[ -f $HMACKEY ]"
ck "hmac key mode 0600"                 "[ \"\$(stat -c %a $HMACKEY 2>/dev/null)\" = '600' ]"
ck "hmac key owned by root"             "[ \"\$(stat -c %U $HMACKEY 2>/dev/null)\" = 'root' ]"
ck "nftables base ruleset present"      "[ -f $NFTFILE ]"
ck "no shell=True in controller"        "! grep -q 'shell=True' $CTL"

echo
echo "== AC-1: at most one ETH UP =="
up=$(ip -br link | awk '$2=="UP" && $1 ~ /^eth/ {print $1}')
if [ "$(echo "$up" | wc -w)" -le 1 ]; then
    ok "one-eth-up (current: ${up:-none})"
else
    bad "one-eth-up (both up: $up)"
fi

echo
echo "== AC-3: firewall at rest =="
if nft list table inet diode >/dev/null 2>&1; then
    rules=$(nft -a list chain inet diode input 2>/dev/null \
            | grep -c "ct state new counter accept" || true)
    if [ "${rules:-0}" -eq 0 ]; then
        ok "no-app-accept-at-rest"
    else
        bad "no-app-accept-at-rest ($rules rules)"
    fi
    pol_in=$(nft  list chain inet diode input  2>/dev/null \
             | grep -o 'policy [a-z]*' | awk '{print $2}')
    pol_out=$(nft list chain inet diode output 2>/dev/null \
             | grep -o 'policy [a-z]*' | awk '{print $2}')
    pol_fw=$(nft  list chain inet diode forward 2>/dev/null \
             | grep -o 'policy [a-z]*' | awk '{print $2}')
    ck "input policy drop"   "[ \"$pol_in\"  = drop ]"
    ck "output policy drop"  "[ \"$pol_out\" = drop ]"
    ck "forward policy drop" "[ \"$pol_fw\"  = drop ]"
else
    bad "table inet diode not loaded"
fi

echo
echo "== AC-4: SIGTERM brings links down =="
if [ -x "$CTL" ] && [ -f "$CFG" ]; then
    "$CTL" --config "$CFG" --once >/dev/null 2>&1 &
    pid=$!
    sleep 2
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    up=$(ip -br link | awk '$2=="UP" && $1 ~ /^eth/ {print}' | wc -l)
    ck "sigterm-links-down" "[ \"$up\" -eq 0 ]"
else
    bad "sigterm-links-down (prereq missing)"
fi

echo
echo "== AC-2: insecure URL rejected by fetch worker =="
if [ -x "$CTL" ]; then
    if "$CTL" --fetch-worker --url "http://insecure.example/x" \
              --dest /tmp/diode-test.bin --ca /etc/ssl/certs/ca-certificates.crt \
              --timeout 5 --max-bytes 1000 --max-redirects 1 \
              >/dev/null 2>&1; then
        bad "http-url-rejected (fetch unexpectedly succeeded)"
    else
        ok "http-url-rejected"
    fi
else
    bad "http-url-rejected (controller missing)"
fi

echo
echo "== Summary: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
bash
chmod +x data-diode-pi/diode-controller.py data-diode-pi/install.sh data-diode-pi/lockdown-services.sh data-diode-pi/tests/acceptance.sh
bash -n data-diode-pi/install.sh && bash -n data-diode-pi/lockdown-services.sh && bash -n data-diode-pi/tests/acceptance.sh && python3 -m py_compile data-diode-pi/diode-controller.py && nft -c -f data-diode-pi/nftables-diode.conf && echo SYNTAX_OK
Read data-diode-pi/README.md first.