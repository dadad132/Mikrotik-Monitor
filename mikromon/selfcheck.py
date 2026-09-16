"""Check the things that have actually gone wrong, and say so on the panel.

Every serious fault this system has had shared one property: it was silent.
A systemd unit that failed on every trigger while its status line said
nothing anybody read. A peers file that was perfect on disk while the kernel
had lost half of it. A service that reported success because its last
command happened to be a `while` loop. A router reporting a dash for "update
available" because one refused check had written off the whole day.

None of those needed cleverness to find. They needed somebody to look, and
nothing was looking.

So this is deliberately not a generic health framework. It is a list of the
specific failures that have cost real days, each phrased as the question that
would have caught it, and each carrying the command that fixes it.
"""
from __future__ import annotations

import os
import subprocess
import time

# A check answers one question. `ok` False means act; `fix` is the command.
# `warn` means worth knowing but nothing is broken right now.


def _finding(cid, ok, title, detail="", fix="", warn=False):
    return {"id": cid, "ok": bool(ok), "title": title, "detail": detail,
            "fix": fix, "warn": bool(warn)}


def _run(cmd, timeout=6):
    """(rc, stdout, stderr). rc None when the command does not exist."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except FileNotFoundError:
        return None, "", "not installed"
    except Exception as exc:  # noqa: BLE001
        return None, "", str(exc)


def _unit_state(unit):
    """"active" / "failed" / "inactive" / "" when systemd is not here."""
    rc, out, _ = _run(["systemctl", "is-failed", unit])
    if rc is None:
        return ""
    if out == "failed":
        return "failed"
    rc2, out2, _ = _run(["systemctl", "is-active", unit])
    return out2 or "inactive"


def check_units():
    """The units that do the work nobody watches.

    A oneshot unit that fails on every trigger looks identical to one that
    has simply finished, unless somebody asks. Remote access was broken from
    the day it shipped because nothing ever asked.
    """
    out = []
    for unit, what, why in (
        ("easymikrotik-access-reload.service",
         "Remote access (WebFig / Winbox)",
         "Without this, a grant is recorded and no port is ever opened -- "
         "the link works out to 'connection refused'."),
        ("mikromon-wg-reload.service",
         "WireGuard peer reload",
         "Without this, a newly provisioned router is written to the peers "
         "file and never loaded, so the hub discards everything it sends."),
    ):
        state = _unit_state(unit)
        if not state:
            continue                    # not a systemd host; nothing to say
        if state == "failed":
            rc, out_txt, _ = _run(
                ["systemctl", "status", "--no-pager", "-n", "5", unit])
            out.append(_finding(
                f"unit:{unit}", False,
                f"{what}: its service is FAILING",
                (out_txt or "").strip()[-600:],
                f"sudo systemctl status {unit} --no-pager"))
        else:
            out.append(_finding(f"unit:{unit}", True, f"{what}: service OK"))
    return out


def check_wg_readable(iface="wg0"):
    """Can we see what WireGuard is actually running?

    This one question was unanswerable for a week, and in that time a key
    mismatch, a peer the hub never loaded, and a site blocking UDP all
    presented as "the router is offline".
    """
    rc, _, err = _run(["wg", "show", iface, "dump"])
    if rc is None:
        return [_finding("wg:read", False, "wireguard-tools is not installed",
                         err, "sudo apt-get install -y wireguard-tools")]
    if rc == 0:
        return [_finding("wg:read", True, "WireGuard state is readable")]
    rc2, _, _ = _run(["sudo", "-n", "wg", "show", iface, "dump"])
    if rc2 == 0:
        return [_finding("wg:read", True,
                         "WireGuard state is readable (via sudo)")]
    user = os.environ.get("USER") or "mikromon"
    return [_finding(
        "wg:read", False,
        "Cannot read what WireGuard is actually running",
        "Without this the Tunnel health table cannot tell a router whose key "
        "is wrong from one whose packets never arrive -- two problems with "
        "opposite fixes. It is the single most useful fact about a tunnel.",
        f"echo '{user} ALL=(root) NOPASSWD: /usr/bin/wg show *' "
        f"| sudo tee /etc/sudoers.d/mikromon-wg")]


def check_peers_dir(peers_path):
    """Can the peers file be REPLACED, not just rewritten?

    Writing it in place means a reader can catch it half-written, and
    `wg syncconf` applies whatever it managed to read -- dropping every peer
    it did not see. That took the whole fleet down repeatedly.
    """
    if not peers_path:
        return []
    d = os.path.dirname(os.path.abspath(peers_path)) or "."
    if not os.path.isdir(d):
        return [_finding("wg:dir", False, f"{d} does not exist", "",
                         "sudo bash deploy/install.sh")]
    if os.access(d, os.W_OK):
        return [_finding("wg:dir", True,
                         "Peers file can be replaced atomically")]
    return [_finding(
        "wg:dir", False,
        f"{d} is not writable, so the peers file cannot be replaced atomically",
        "It is still written, in place, which leaves a narrow window where a "
        "reload can read it mid-write and apply a stale peer list.",
        f"sudo chmod 770 {d} && sudo chmod 600 {d}/wg0.key", warn=True)]


def check_peers_file(peers_path, expected_peers=None):
    """A peers file with nothing in it while routers are registered."""
    if not peers_path or not os.path.exists(peers_path):
        return []
    try:
        body = open(peers_path, encoding="utf-8").read()
    except OSError as exc:
        return [_finding("wg:file", False, "Cannot read the peers file",
                         str(exc))]
    have = body.count("PublicKey")
    if expected_peers and have == 0:
        return [_finding(
            "wg:file", False,
            f"The peers file is EMPTY while {expected_peers} routers are "
            f"registered",
            "Every router will be discarded by the hub until this is "
            "rewritten.",
            "Platform admin -> Reload hub peers now")]
    return [_finding("wg:file", True,
                     f"Peers file holds {have} peer(s)")]


def check_nginx(access_cfg):
    """nginx has to exist and be running for remote access to work at all."""
    if not (access_cfg or {}).get("nginx_http_conf"):
        return []
    rc, _, _ = _run(["nginx", "-v"])
    if rc is None:
        return [_finding("nginx:present", False,
                         "Remote access is configured but nginx is not "
                         "installed", "",
                         "sudo apt-get install -y nginx libnginx-mod-stream")]
    state = _unit_state("nginx.service")
    if state and state != "active":
        return [_finding("nginx:running", False,
                         f"nginx is {state} -- remote access cannot work", "",
                         "sudo systemctl start nginx")]
    rc2, _, err2 = _run(["nginx", "-t"])
    if rc2 not in (0, None):
        return [_finding("nginx:conf", False,
                         "nginx refuses its own configuration",
                         (err2 or "")[-400:],
                         "sudo nginx -t")]
    return [_finding("nginx:running", True, "nginx is running and its "
                                            "configuration is valid")]


def check_retention(metrics_db, retention_days=30):
    """Is old data actually being pruned?

    Retention used to be enforced only at startup, so a long-running server
    kept every sample it had ever taken and the dashboard got slower every
    day -- 25 seconds to draw one page, in the end.
    """
    if not metrics_db or not os.path.exists(metrics_db):
        return []
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{metrics_db}?mode=ro", uri=True)
        try:
            row = con.execute("SELECT MIN(ts) FROM samples").fetchone()
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        return [_finding("metrics:read", False,
                         "Cannot read the metrics database", str(exc))]
    oldest = (row or [None])[0]
    if not oldest:
        return []
    age_days = (time.time() - oldest) / 86400
    size_mb = os.path.getsize(metrics_db) / 1e6
    # A day's slack: pruning runs hourly, so the oldest sample sits just
    # inside the window rather than exactly on it.
    if age_days > retention_days + 1:
        return [_finding(
            "metrics:retention", False,
            f"Metrics go back {age_days:.0f} days but retention is "
            f"{retention_days} ({size_mb:.0f} MB)",
            "Old samples are not being pruned. Every dashboard read gets "
            "slower as this grows.",
            "sudo systemctl restart mikromon", warn=True)]
    return [_finding("metrics:retention", True,
                     f"Metrics retention is working "
                     f"({age_days:.0f} days, {size_mb:.0f} MB)")]


def check_smtp(smtp_cfg):
    """Alerts nobody receives are not alerts."""
    if isinstance(smtp_cfg, dict):
        host = str(smtp_cfg.get("host", "") or "").strip()
    else:
        host = str(getattr(smtp_cfg, "host", "") or "").strip() if smtp_cfg else ""
    if host:
        return [_finding("smtp", True, "Email is configured")]
    return [_finding(
        "smtp", False, "No email server is configured",
        "Every alert this system raises has nowhere to go.",
        "Platform admin -> Email (SMTP) settings", warn=True)]


def check_deployed_version(app_dir=""):
    """Is the code that is RUNNING the code that was last pulled?

    The app directory is an rsync of the checkout, not the checkout itself,
    so `git pull` updates the source and changes nothing that runs. The only
    symptom is a fix that appears not to work -- which has cost real time
    here, more than once, with everyone assuming the fix was wrong.
    """
    # Where the running code actually lives -- not the working directory,
    # which is whatever systemd or a shell happened to set.
    app_dir = app_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    vpath = os.path.join(app_dir, "VERSION")
    running = ""
    when = ""
    try:
        parts = open(vpath, encoding="utf-8").read().split()
        running = parts[0] if parts else ""
        when = parts[1] if len(parts) > 1 else ""
    except OSError:
        pass
    if not running or running == "unknown":
        return [_finding(
            "version", True,
            "Running version is not recorded",
            "Re-run the installer once and it will be, so the next time a "
            "fix seems not to have taken you can tell at a glance whether "
            "it is even deployed.", "sudo bash deploy/install.sh", warn=True)]

    # If a checkout is sitting next to us, say whether it has moved on.
    rc, head, _ = _run(["git", "-C", app_dir, "rev-parse", "--short", "HEAD"])
    if rc == 0 and head and head != running:
        return [_finding(
            "version", False,
            f"The running code is {running}, but this checkout is at {head}",
            "A pull updates the checkout; the service runs an rsynced copy. "
            "Until the installer is re-run, nothing you pulled is live.",
            "sudo bash deploy/install.sh")]
    detail = f"deployed {when}" if when else ""
    return [_finding("version", True, f"Running version {running}", detail)]


def run_all(*, peers_path="", expected_peers=0, access_cfg=None,
            metrics_db="", retention_days=30, smtp_cfg=None, app_dir=""):
    """Every check, in the order a person would want to read them."""
    out = []
    for fn in (lambda: check_deployed_version(app_dir),
               lambda: check_units(),
               lambda: check_wg_readable(),
               lambda: check_peers_dir(peers_path),
               lambda: check_peers_file(peers_path, expected_peers),
               lambda: check_nginx(access_cfg),
               lambda: check_retention(metrics_db, retention_days),
               lambda: check_smtp(smtp_cfg)):
        try:
            out.extend(fn() or [])
        except Exception as exc:  # noqa: BLE001 — one check must not stop the rest
            out.append(_finding("selfcheck:error", False,
                                "A self-check failed to run", str(exc)))
    # Broken first, then warnings, then what is fine: the order somebody
    # scans a list in when they came here because something is wrong.
    out.sort(key=lambda f: (f["ok"], f["warn"]))
    return out
