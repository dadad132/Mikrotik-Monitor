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
    # `nginx -t` has to read the TLS key, which is root-only. Run as the web
    # service user it therefore fails on a PERFECTLY GOOD config -- and then
    # says so in red, on the page people open when something is wrong. A
    # check that cannot tell working from broken is worse than no check: it
    # sends you after the wrong thing, which is exactly what it did here.
    rc2, _, err2 = _run(["nginx", "-t"])
    if rc2 not in (0, None):
        rc3, _, err3 = _run(["sudo", "-n", "nginx", "-t"])
        if rc3 == 0:
            return [_finding("nginx:running", True, "nginx is running and "
                                                    "its configuration is valid")]
        if rc3 is not None and _denied(err2) and _denied(err3):
            user = os.environ.get("USER") or "mikromon"
            return [_finding(
                "nginx:conf", True,
                "Could not verify the nginx configuration",
                "Testing it means reading the TLS private key, which only "
                "root may do -- so this says nothing either way about nginx.",
                f"echo '{user} ALL=(root) NOPASSWD: /usr/sbin/nginx -t' "
                f"| sudo tee /etc/sudoers.d/mikromon-nginx", warn=True)]
        return [_finding("nginx:conf", False,
                         "nginx refuses its own configuration",
                         ((err3 or err2) or "")[-400:],
                         "sudo nginx -t")]
    return [_finding("nginx:running", True, "nginx is running and its "
                                            "configuration is valid")]


def check_access_host(access_cfg):
    """Can anyone actually OPEN the remote-access links this server hands out?

    `access.hub_host` is detected at install time, and the detection falls
    back to `hostname -I` when the public-IP lookup fails. On a server behind
    NAT that yields a 172.16.x.x address: grants are created, nginx listens,
    every green tick stays green -- and the browser times out, because the
    address in the link exists only on the server's own LAN.
    """
    host = str((access_cfg or {}).get("hub_host", "") or "").strip()
    if not host:
        return []
    if not _unroutable_host(host):
        return [_finding("access:host", True,
                         f"Remote-access links point at {host}")]
    return [_finding(
        "access:host", False,
        f"Remote-access links point at {host}, which only works inside this "
        f"server's own network",
        "This is a private address. WebFig and Winbox links built from it "
        "time out for anyone browsing from anywhere else -- the port really "
        "is open, the address just does not reach it. Links now fall back to "
        "whatever address the browser used to reach the dashboard, so set "
        "this to the public hostname to make it deliberate.",
        "sudo ACCESS_HOST=your.public.hostname bash deploy/install.sh")]


def _unroutable_host(host):
    """Private / loopback / link-local. A hostname is assumed routable."""
    import ipaddress
    h = (host or "").strip().strip("[]").split("%")[0]
    if not h or h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_unspecified)


def _denied(err):
    return "permission denied" in (err or "").lower()


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


def _cert_days_left(path):
    """Days until this certificate expires, or None if it cannot be read.

    Uses openssl rather than parsing X.509 by hand: it is already installed
    (the installer uses it to make the fallback cert) and it is the same
    answer the browser will reach.
    """
    rc, out, _ = _run(["openssl", "x509", "-enddate", "-noout", "-in", path])
    if rc != 0 or "notAfter=" not in (out or ""):
        return None
    when = out.split("notAfter=", 1)[1].strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            import calendar
            import time as _t
            return (calendar.timegm(_t.strptime(when, fmt)) - time.time()) / 86400
        except ValueError:
            continue
    return None


def _cert_paths(access_cfg):
    """Every certificate this server actually serves."""
    import glob
    paths = []
    cert = str((access_cfg or {}).get("tls_cert") or "").strip()
    if cert:
        paths.append(cert)
    paths.extend(sorted(glob.glob("/etc/letsencrypt/live/*/fullchain.pem")))
    seen = set()
    return [p for p in paths if os.path.exists(p)
            and not (p in seen or seen.add(p))]


def check_tls_expiry(access_cfg=None, warn_days=21, critical_days=7):
    """How long until the certificate stops working?

    Let's Encrypt certificates last 90 days and are meant to renew
    themselves. When that quietly stops, nothing says so until the browser
    does -- and by then it is everybody's problem at once, including the
    remote-access links and any router dialling in over HTTPS.

    Let's Encrypt no longer emails expiry warnings, so if this server does
    not look, nothing is looking.
    """
    out = []
    for path in _cert_paths(access_cfg):
        days = _cert_days_left(path)
        name = os.path.basename(os.path.dirname(path)) or os.path.basename(path)
        if days is None:
            out.append(_finding(f"tls:{path}", False,
                                f"Cannot read the certificate for {name}",
                                path, f"sudo openssl x509 -noout -text -in {path}",
                                warn=True))
        elif days < 0:
            out.append(_finding(
                f"tls:{path}", False,
                f"The certificate for {name} EXPIRED {abs(days):.0f} days ago",
                "Browsers are refusing this site now.",
                "sudo certbot renew --force-renewal && sudo systemctl reload nginx"))
        elif days < critical_days:
            out.append(_finding(
                f"tls:{path}", False,
                f"The certificate for {name} expires in {days:.0f} days",
                "Renewal should have happened at 30 days and has not, so it "
                "is not going to happen on its own before this runs out.",
                "sudo certbot renew --dry-run   # then: sudo certbot renew"))
        elif days < warn_days:
            out.append(_finding(
                f"tls:{path}", False,
                f"The certificate for {name} expires in {days:.0f} days",
                "Still time, but renewal normally happens at 30 days, so "
                "something is already not working.",
                "sudo certbot renew --dry-run", warn=True))
        else:
            out.append(_finding(f"tls:{path}", True,
                                f"Certificate for {name} is good for "
                                f"{days:.0f} more days"))
    return out


def check_cert_renewal():
    """Is anything actually going to renew the certificate?

    The installer used to print "Cert auto-renews via certbot systemd timer"
    without ever asking whether that timer exists or runs. It is the same
    shape as every other fault this system has had: a reassuring line of
    output that nothing checked.
    """
    rc, _, _ = _run(["certbot", "--version"])
    if rc is None:
        return []                       # no certbot; nothing to say
    for unit in ("certbot.timer", "snap.certbot.renew.timer"):
        state = _unit_state(unit)
        if state == "active":
            return [_finding("tls:renew", True,
                             f"Certificate renewal is armed ({unit})")]
        if state and state != "inactive":
            continue
    return [_finding(
        "tls:renew", False,
        "Nothing is scheduled to renew the TLS certificate",
        "Let's Encrypt certificates last 90 days. Without the timer they "
        "simply run out, and the first sign is the browser refusing the "
        "site.",
        "sudo systemctl enable --now certbot.timer")]


def check_zoho(app_dir="", settings=None):
    """Are the Zoho credentials actually on this server, and usable?

    Credentials that were set up correctly somewhere else are worth nothing
    here. This says whether the refresh token exists, without ever printing
    it.
    """
    cfg = dict(settings or {})
    src = "settings"
    if not cfg.get("refresh_token"):
        app_dir = app_dir or os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(app_dir, "zoho-oauth.json")
        if not os.path.exists(path):
            return []                   # not set up; not a fault
        src = path
        try:
            import json
            cfg = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [_finding("zoho", False,
                             "The Zoho credentials file cannot be read",
                             f"{path}: {exc}",
                             "python3 tools/zoho_setup.py")]
    if not cfg.get("refresh_token"):
        return [_finding(
            "zoho", False, "Zoho is half set up: no refresh token",
            f"Found in {src}, but without the refresh token nothing can "
            f"authenticate. The grant code was probably never exchanged.",
            "python3 tools/zoho_setup.py")]
    org = str(cfg.get("organization_name") or cfg.get("organization_id") or "")
    dc = str(cfg.get("accounts_host") or "")
    return [_finding("zoho", True,
                     f"Zoho credentials are present{f' for {org}' if org else ''}",
                     f"{dc}  (from {os.path.basename(str(src))})")]


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
            metrics_db="", retention_days=30, smtp_cfg=None,
            app_dir="", zoho_cfg=None):
    """Every check, in the order a person would want to read them."""
    out = []
    for fn in (lambda: check_deployed_version(app_dir),
               lambda: check_units(),
               lambda: check_wg_readable(),
               lambda: check_peers_dir(peers_path),
               lambda: check_peers_file(peers_path, expected_peers),
               lambda: check_access_host(access_cfg),
               lambda: check_tls_expiry(access_cfg),
               lambda: check_cert_renewal(),
               lambda: check_zoho(app_dir, zoho_cfg),
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
