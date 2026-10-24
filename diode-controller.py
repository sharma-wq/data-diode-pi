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