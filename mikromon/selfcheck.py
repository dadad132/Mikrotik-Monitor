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


_SMTP_CACHE: dict = {}
_SMTP_CACHE_SECONDS = 300
_SMTP_RUNNING: set = set()
_SMTP_LOCK = __import__("threading").Lock()


def _smtp_cache(key, findings):
    _SMTP_CACHE[key] = (time.time(), list(findings))
    return findings


def _smtp_field(cfg, name, default=""):
    if isinstance(cfg, dict):
        return cfg.get(name, default)
    return getattr(cfg, name, default) if cfg else default


def check_smtp(smtp_cfg, probe: bool = True):
    """Does email actually work -- not "is a host written in the settings".

    The old version answered the second question and reported the first.
    "Email is configured" was equally true of a host that does not resolve,
    a port nothing listens on, a password rotated last month, and a TLS
    handshake that fails. Every alert this system raises goes down this
    path, so a tick that cannot tell those from a working relay is worse
    than no tick: it is why nobody looks twice.

    The probe connects, negotiates TLS and logs in. It never sends a
    message, so it is safe to run on every page load.
    """
    host = str(_smtp_field(smtp_cfg, "host", "") or "").strip()
    if not host:
        return [_finding(
            "smtp", False, "No email server is configured",
            "Every alert this system raises has nowhere to go.",
            "Platform admin -> Email (SMTP) settings", warn=True)]
    if not probe:
        return [_finding("smtp", True, f"Email is configured ({host})")]

    # The probe NEVER runs inline. This is the page somebody opens
    # because something is already broken, and a mail server that is
    # slow or firewalled would make it indistinguishable from a dead
    # dashboard -- eight seconds of nothing, on the one page they need
    # right then.
    key = f"{host}:{_smtp_field(smtp_cfg, 'port', '')}:" + str(_smtp_field(smtp_cfg, "username", ""))
    hit = _SMTP_CACHE.get(key)
    if not (hit and time.time() - hit[0] < _SMTP_CACHE_SECONDS):
        _probe_smtp_async(key, smtp_cfg)
    if hit:
        return list(hit[1])
    return [_finding("smtp", True, f"Checking email ({host})\u2026",
                     "The result appears here once the mail server "
                     "answers. It is checked in the background so this "
                     "page never waits on it.")]


def _probe_smtp_async(key, smtp_cfg) -> None:
    """Start one background probe for this configuration, at most.

    At most one, because the panel reloads and a probe per reload would
    open a connection to somebody's mail server every few seconds --
    which is how a health check becomes the thing being complained
    about.
    """
    import threading
    with _SMTP_LOCK:
        if key in _SMTP_RUNNING:
            return
        _SMTP_RUNNING.add(key)

    def run():
        try:
            _SMTP_CACHE[key] = (time.time(), _probe_smtp(smtp_cfg))
        except Exception:  # noqa: BLE001 - never take a thread out
            log.exception("the SMTP probe failed")
        finally:
            with _SMTP_LOCK:
                _SMTP_RUNNING.discard(key)

    threading.Thread(target=run, name="mikromon-smtp-probe",
                     daemon=True).start()


def _probe_smtp(smtp_cfg):
    """Connect, negotiate TLS and sign in. Never sends a message.

    Runs on a background thread. Nothing here may be called from inside
    a request.
    """
    host = str(_smtp_field(smtp_cfg, "host", "") or "").strip()
    import smtplib
    import socket
    import ssl
    port = int(_smtp_field(smtp_cfg, "port", 0) or 0)
    use_ssl = bool(_smtp_field(smtp_cfg, "use_ssl", False))
    use_tls = bool(_smtp_field(smtp_cfg, "use_tls", True))
    user = str(_smtp_field(smtp_cfg, "username", "") or "")
    pwd = str(_smtp_field(smtp_cfg, "password", "") or "")
    port = port or (465 if use_ssl else 587)

    try:
        ctx = ssl.create_default_context()
        if use_ssl:
            srv = smtplib.SMTP_SSL(host, port, timeout=8, context=ctx)
        else:
            srv = smtplib.SMTP(host, port, timeout=8)
        try:
            srv.ehlo()
            if not use_ssl and use_tls:
                srv.starttls(context=ctx)
                srv.ehlo()
            if user:
                srv.login(user, pwd)
            srv.noop()
        finally:
            try:
                srv.quit()
            except Exception:  # noqa: BLE001
                pass
    except smtplib.SMTPAuthenticationError as exc:
        return [_finding(
            "smtp", False, "The email server rejected our sign-in",
            f"{host}:{port} answered: {str(exc)[:200]}. Every alert this "
            f"system raises is going nowhere.",
            "Platform admin -> Email (SMTP) settings")]
    except (smtplib.SMTPException, socket.timeout, socket.error, OSError,
            ssl.SSLError) as exc:
        return [_finding(
            "smtp", False, f"Cannot reach the email server ({host}:{port})",
            f"{type(exc).__name__}: {str(exc)[:200]}. Every alert this "
            f"system raises is going nowhere.",
            f"telnet {host} {port}   # from this server")]
    detail = "signed in successfully" if user else "connected (no sign-in)"
    return [_finding("smtp", True, f"Email works ({host}:{port})",
                     detail)]


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


def check_https_enforced(config_path="", access_cfg=None):
    """Is the dashboard reachable over plain HTTP?

    The symptom is a browser saying "Not secure" on a site that has a
    perfectly good certificate. Two separate things cause it, and both are
    invisible from inside the app:

    `secure_cookies` decides whether the session cookie carries the Secure
    attribute at all. install.sh leaves it false whenever the certificate
    was not yet in place on its first run -- which is every server where the
    domain was pointed at it afterwards -- and nothing ever turns it back
    on. So a site with a real Let's Encrypt cert can be sending its session
    cookie over plain HTTP, which is the one that actually costs something.

    And without HSTS the browser has no reason to prefer https: one http
    link, one typed address, one old bookmark, and the whole session is in
    the clear with nothing to say so.
    """
    import glob
    out = []
    live = sorted(glob.glob("/etc/letsencrypt/live/*/fullchain.pem"))
    if not live:
        return []                       # no cert, nothing to enforce yet

    secure = None
    if config_path and os.path.exists(config_path):
        try:
            import yaml
            with open(config_path, encoding="utf-8") as f:
                secure = bool((yaml.safe_load(f) or {}).get("secure_cookies"))
        except Exception:  # noqa: BLE001
            secure = None
    if secure is False:
        out.append(_finding(
            "https:cookie", False,
            "The session cookie is NOT marked Secure, on a server that has "
            "a certificate",
            "secure_cookies is false in config.yaml. It is set at install "
            "time and left false when the certificate was not yet in place "
            "on that first run, so a server that got its domain afterwards "
            "stays like this. The cookie is then sent over plain HTTP "
            "whenever anything reaches the site that way.",
            "Set secure_cookies: true in config.yaml, then: "
            "sudo systemctl restart mikromon-web"))
    elif secure:
        out.append(_finding("https:cookie", True,
                            "The session cookie is marked Secure"))

    hsts = False
    for conf in ("/etc/nginx/sites-enabled/easymikrotik",
                 "/etc/nginx/sites-available/easymikrotik"):
        try:
            with open(conf, encoding="utf-8") as f:
                if "Strict-Transport-Security" in f.read():
                    hsts = True
                    break
        except OSError:
            continue
    if not hsts:
        out.append(_finding(
            "https:hsts", False,
            "Browsers are not told to insist on HTTPS",
            "There is no Strict-Transport-Security header, so http:// still "
            "works and a browser has no reason to prefer https. One old "
            "bookmark or one plain link and the session runs in the clear "
            "with only a small 'Not secure' in the address bar to say so.",
            "Add to the 443 server block in "
            "/etc/nginx/sites-available/easymikrotik:\n"
            '  add_header Strict-Transport-Security '
            '"max-age=31536000" always;\n'
            "then: sudo nginx -t && sudo systemctl reload nginx",
            warn=True))
    else:
        out.append(_finding("https:hsts", True,
                            "Browsers are told to insist on HTTPS"))
    return out


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


def check_billing_ready(billing_db="", card_ready=None,
                        runner_status=None, pay_base=None):
    """Companies on a paid packet that will never be invoiced.

    Renewal invoicing selects on the paid-up date, so a company without one
    is skipped every pass. Activating a packet by hand used to leave it
    unset, which produced an account that is correct in every visible way --
    active, right packet, right device cap -- and silently never billed.

    This is the only fault here whose symptom is money not arriving, so it
    is worth asking about on a page somebody already looks at.
    """
    if not billing_db or not os.path.exists(billing_db):
        return []
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{billing_db}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT org_id, plan FROM billing "
                "WHERE current_period_end IS NULL "
                "AND plan IS NOT NULL AND plan != '' "
                "AND plan != 'unlimited' "
                "AND status IN ('active','grace')").fetchall()
        finally:
            con.close()
    except Exception:  # noqa: BLE001 — no billing table yet is not a fault
        return []
    out = []
    if rows:
        who = ", ".join(f"company {r[0]} ({r[1]})" for r in rows[:5])
        out.append(_finding(
            "billing:never", False,
            f"{len(rows)} paid company(ies) will never be invoiced",
            f"{who}. They are on a priced packet with no paid-up date, and "
            f"renewal invoicing only considers companies that have one. "
            f"Nothing else about these accounts looks wrong.",
            "Platform admin -> Billing -> re-save the packet for each"))
    if runner_status is not None and runner_status.get("started"):
        ran = float(runner_status.get("ran") or 0.0)
        age = (time.time() - ran) / 60 if ran else None
        if ran and age is not None and age > 45:
            out.append(_finding(
                "billing:runner", False,
                f"The billing pass has not run for {age:.0f} minutes",
                "It runs every 15. Either the thread has died or a pass is "
                "hanging -- invoices are not going out, and nothing else "
                "would say so.",
                "sudo systemctl restart mikromon-web"))
        elif not ran and (time.time() - float(
                runner_status.get("started") or 0.0)) > 3600:
            out.append(_finding(
                "billing:runner", False,
                "The billing pass has never run since this server started",
                "It should run within 15 minutes of startup.",
                "journalctl -u mikromon-web | grep billing"))
        elif runner_status.get("error"):
            out.append(_finding(
                "billing:runner", False, "The last billing pass failed",
                str(runner_status["error"])[:300],
                "journalctl -u mikromon-web -n 100 | grep -i billing"))
        elif ran:
            out.append(_finding(
                "billing:runner", True,
                f"Billing pass ran {age:.0f} minute(s) ago"))
    if pay_base is not None and not pay_base:
        out.append(_finding(
            "billing:paylink", False,
            "Invoices are going out with no way to pay them",
            "Every invoice links to this server's public address, and none "
            "is set -- so the link is left off and every renewal falls back "
            "to somebody here reading a bank statement. It sets itself the "
            "first time Platform admin is opened on the public domain "
            "rather than an IP.",
            "Open https://your.domain/superadmin once"))
    elif pay_base:
        out.append(_finding("billing:paylink", True,
                            f"Invoices link to {pay_base}/pay"))
    if card_ready is False:
        out.append(_finding(
            "billing:provider", False,
            "Card payment is not switched on",
            "Invoices still go out, but the link on them cannot take a "
            "payment -- so every renewal needs somebody here to record a "
            "bank transfer by hand.",
            "Platform admin -> Yoco", warn=True))
    if not out:
        out.append(_finding("billing:never", True,
                            "Every paid company has a renewal date"))
    return out


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
            app_dir="", billing_db="", config_path="",
            card_ready=None, runner_status=None, pay_base=None):
    """Every check, in the order a person would want to read them."""
    out = []
    for fn in (lambda: check_deployed_version(app_dir),
               lambda: check_units(),
               lambda: check_wg_readable(),
               lambda: check_peers_dir(peers_path),
               lambda: check_peers_file(peers_path, expected_peers),
               lambda: check_access_host(access_cfg),
               lambda: check_tls_expiry(access_cfg),
               lambda: check_https_enforced(config_path, access_cfg),
               lambda: check_cert_renewal(),
               lambda: check_billing_ready(billing_db, card_ready,
                                           runner_status, pay_base),
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
