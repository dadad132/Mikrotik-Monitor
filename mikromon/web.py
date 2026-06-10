"""Web dashboard + JSON API + Prometheus endpoint, with multi-user auth.

Runs as a separate process from `mikromon run` (they share the metrics DB and
state.json). When an `auth_db` is configured, every page requires a login and
all data is filtered to the devices the logged-in user is allowed to see, so
users never see each other's routers. Admins manage users from /admin.

Endpoints:
  GET  /                 dashboard (scoped to the user's devices)
  GET  /login  POST      login form / authenticate
  GET  /logout           end session
  GET  /admin  POST .../ user management (admins only)
  GET  /api/devices      JSON, scoped
  GET  /api/series?...   JSON time-series (device must be permitted)
  GET  /metrics          Prometheus (admin session, or ?token=/Bearer metrics_token)
  GET  /health           "ok"
"""
from __future__ import annotations

import html
import json
import logging
import os
import re
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .auth import AuthStore
from .metrics import MetricsStore
from .util import human_bps

log = logging.getLogger(__name__)

_PROM_SAFE = re.compile(r"[^a-zA-Z0-9_]")
_COOKIE = "mikromon_session"
_SESSION_TTL = 12 * 3600


# ============================ data assembly ================================
def _load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"devices": {}}


def _problems(conditions: dict) -> list:
    out = []
    for key, cond in (conditions or {}).items():
        if cond.get("status") == "problem" or cond.get("level") in ("warn", "crit"):
            out.append({"key": key, "since": cond.get("since"),
                        "level": cond.get("level", "problem")})
    return out


def _device_view(store, state, name) -> dict:
    latest = store.latest(name)
    conditions = state.get("devices", {}).get(name, {}).get("conditions", {})
    metrics, throughput = {}, {}
    for (metric, label), rec in latest.items():
        if metric in ("rx_bps", "tx_bps"):
            throughput.setdefault(label, {})[metric] = rec["value"]
        else:
            metrics[metric] = rec["value"]
    up = metrics.get("up")
    if up is None:
        rc = conditions.get("reachability", {})
        up = 0 if rc.get("status") == "problem" else 1
    return {"device": name, "up": int(up), "metrics": metrics,
            "throughput": throughput, "problems": _problems(conditions)}


def _known_devices(store, state) -> list:
    return sorted(set(store.devices()) | set(state.get("devices", {}).keys()))


def _all_devices(store, state, allowed=None) -> list:
    names = _known_devices(store, state)
    if allowed is not None:
        names = [n for n in names if n in allowed]
    return [_device_view(store, state, n) for n in names]


# ============================ rendering ====================================
def _sparkline(points, width=160, height=36) -> str:
    vals = [v for _, v in points]
    if len(vals) < 2:
        return f'<svg width="{width}" height="{height}"></svg>'
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1.0
    step = width / (len(vals) - 1)
    coords = " ".join(
        f"{i * step:.1f},{height - 2 - (v - lo) / rng * (height - 4):.1f}"
        for i, v in enumerate(vals))
    return (f'<svg width="{width}" height="{height}" style="vertical-align:middle">'
            f'<polyline fill="none" stroke="#2563eb" stroke-width="1.5" '
            f'points="{coords}"/></svg>')


_PAGE_CSS = """
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f3f4f6;color:#111}
 header{background:#111827;color:#fff;padding:12px 20px;display:flex;
   justify-content:space-between;align-items:center}
 header a{color:#93c5fd;text-decoration:none;margin-left:14px}
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
   gap:16px;padding:20px}
 .card{background:#fff;border-radius:10px;padding:14px 18px;
   box-shadow:0 1px 3px rgba(0,0,0,.1)}
 .card h2{font-size:16px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
 .dot{width:12px;height:12px;border-radius:50%;display:inline-block}
 .state{margin-left:auto;font-size:11px;color:#6b7280}
 table{width:100%;border-collapse:collapse;font-size:13px}
 td,th{padding:4px 6px;border-bottom:1px solid #f0f0f0;text-align:left}
 .probs{margin-top:8px;color:#b91c1c;font-size:13px}.probs ul{margin:4px 0 0 18px}
 .ok{margin-top:8px;color:#16a34a;font-size:13px}
 .wrap{max-width:900px;margin:30px auto;padding:0 20px}
 form.inline{display:inline} input,select{padding:5px;margin:2px 0}
 .btn{background:#2563eb;color:#fff;border:0;padding:6px 12px;border-radius:6px;
   cursor:pointer}.btn.red{background:#dc2626}
 .box{background:#fff;border-radius:10px;padding:18px;margin:16px 0;
   box-shadow:0 1px 3px rgba(0,0,0,.1)}
"""


def _header(user) -> str:
    right = '<div style="font-size:12px">auto-refresh 10s</div>'
    if user:
        links = ' <a href="/admin">Admin</a>' if user.get("role") == "admin" else ""
        right = (f'<div style="font-size:12px">{html.escape(user["username"])}'
                 f' ({html.escape(user["role"])}){links} '
                 f'<a href="/logout">Log out</a></div>')
    return (f'<header><div><b>mikromon</b> &middot; MikroTik fleet dashboard</div>'
            f'{right}</header>')


def _render_dashboard(store, state, user=None, allowed=None) -> str:
    cards = []
    for d in _all_devices(store, state, allowed):
        up = d["up"]
        dot = "#16a34a" if up else "#dc2626"
        m = d["metrics"]
        rows = []
        if "cpu" in m:
            sp = _sparkline(store.series(d["device"], "cpu", since=time.time() - 3600))
            rows.append(f"<tr><td>CPU</td><td>{m['cpu']:.0f}%</td><td>{sp}</td></tr>")
        if "mem_free_pct" in m:
            rows.append(f"<tr><td>Free RAM</td><td>{m['mem_free_pct']:.0f}%</td>"
                        f"<td></td></tr>")
        if "client_count" in m:
            sp = _sparkline(store.series(d["device"], "client_count",
                                         since=time.time() - 3600))
            rows.append(f"<tr><td>Devices</td><td>{m['client_count']:.0f}</td>"
                        f"<td>{sp}</td></tr>")
        for iface, t in sorted(d["throughput"].items()):
            sp = _sparkline(store.series(d["device"], "rx_bps", label=iface,
                                         since=time.time() - 3600))
            rows.append(f"<tr><td>{html.escape(iface)}</td><td>"
                        f"&darr;{human_bps(t.get('rx_bps', 0))} "
                        f"&uarr;{human_bps(t.get('tx_bps', 0))}</td><td>{sp}</td></tr>")
        probs = "".join(f'<li><b>{html.escape(p["key"])}</b> '
                        f'({html.escape(str(p["level"]))})</li>' for p in d["problems"])
        probs_html = (f'<div class="probs"><b>Active problems:</b><ul>{probs}</ul>'
                      f'</div>' if probs else '<div class="ok">No active problems</div>')
        cards.append(f'<div class="card"><h2><span class="dot" style="background:'
                     f'{dot}"></span>{html.escape(d["device"])}<span class="state">'
                     f'{"ONLINE" if up else "OFFLINE"}</span></h2><table>'
                     f'{"".join(rows)}</table>{probs_html}</div>')
    body = "".join(cards) or "<p style='padding:20px'>No devices to show.</p>"
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="10"><title>mikromon</title>'
            f'<style>{_PAGE_CSS}</style></head><body>{_header(user)}'
            f'<div class="grid">{body}</div></body></html>')


def _render_login(error: str = "") -> str:
    msg = f'<p style="color:#dc2626">{html.escape(error)}</p>' if error else ""
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>'
            f'<style>{_PAGE_CSS}</style></head><body><div class="wrap">'
            f'<div class="box" style="max-width:360px;margin:80px auto">'
            f'<h2>mikromon — sign in</h2>{msg}'
            f'<form method="POST" action="/login">'
            f'<p><input name="username" placeholder="Username" autofocus '
            f'style="width:100%"></p>'
            f'<p><input name="password" type="password" placeholder="Password" '
            f'style="width:100%"></p>'
            f'<button class="btn" type="submit">Sign in</button>'
            f'</form></div></div></body></html>')


def _render_admin(auth: AuthStore, known_devices, csrf: str, user) -> str:
    rows = []
    for u in auth.list_users():
        devs = "*" if u["devices"] == "*" else ", ".join(u["devices"]) or "(none)"
        checks = "".join(
            f'<label><input type="checkbox" name="devices" value="{html.escape(d)}"'
            f'{" checked" if u["devices"] == "*" or d in u["devices"] else ""}> '
            f'{html.escape(d)}</label> ' for d in known_devices)
        rows.append(f"""<tr><td><b>{html.escape(u['username'])}</b></td>
          <td>{html.escape(u['role'])}</td><td>{html.escape(devs)}</td>
          <td><form class="inline" method="POST" action="/admin/update">
            <input type="hidden" name="csrf" value="{csrf}">
            <input type="hidden" name="username" value="{html.escape(u['username'])}">
            <select name="role"><option{' selected' if u['role']=='user' else ''}>user</option>
            <option{' selected' if u['role']=='admin' else ''}>admin</option></select>
            <label><input type="checkbox" name="all"{' checked' if u['devices']=='*' else ''}> all</label>
            {checks}
            <button class="btn" type="submit">Save</button></form>
            <form class="inline" method="POST" action="/admin/delete"
              onsubmit="return confirm('Delete {html.escape(u['username'])}?')">
            <input type="hidden" name="csrf" value="{csrf}">
            <input type="hidden" name="username" value="{html.escape(u['username'])}">
            <button class="btn red" type="submit">Delete</button></form></td></tr>""")
    add_checks = "".join(
        f'<label><input type="checkbox" name="devices" value="{html.escape(d)}"> '
        f'{html.escape(d)}</label> ' for d in known_devices)
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>Users</title>'
            f'<style>{_PAGE_CSS}</style></head><body>{_header(user)}'
            f'<div class="wrap"><h1>User management</h1>'
            f'<div class="box"><table><tr><th>User</th><th>Role</th>'
            f'<th>Devices</th><th>Actions</th></tr>{"".join(rows)}</table></div>'
            f'<div class="box"><h2>Add user</h2>'
            f'<form method="POST" action="/admin/add">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input name="username" placeholder="username"> '
            f'<input name="password" type="password" placeholder="password (min 6)"> '
            f'<select name="role"><option>user</option><option>admin</option></select>'
            f'<br><label><input type="checkbox" name="all"> all devices</label> '
            f'{add_checks}<br><button class="btn" type="submit">Create user</button>'
            f'</form></div>'
            f'<p><a href="/">&larr; back to dashboard</a></p></div></body></html>')


def _render_prometheus(store, allowed=None) -> str:
    lines = []
    for device, metric, label, value, _ts in store.all_latest():
        if allowed is not None and device not in allowed:
            continue
        name = "mikromon_" + _PROM_SAFE.sub("_", metric)
        labels = f'device="{device}"' + (f',name="{label}"' if label else "")
        lines.append(f"{name}{{{labels}}} {value}")
    return "\n".join(lines) + "\n"


# ============================ sessions =====================================
class SessionManager:
    def __init__(self):
        self._s: dict[str, dict] = {}

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        self._s[token] = {"username": username, "expires": time.time() + _SESSION_TTL,
                          "csrf": secrets.token_urlsafe(16)}
        return token

    def get(self, token: str):
        s = self._s.get(token or "")
        if not s:
            return None
        if s["expires"] < time.time():
            self._s.pop(token, None)
            return None
        s["expires"] = time.time() + _SESSION_TTL  # sliding window
        return s

    def destroy(self, token: str) -> None:
        self._s.pop(token or "", None)


# ============================ HTTP handler =================================
def make_handler(metrics_db, state_file, auth: AuthStore | None,
                 sessions: SessionManager, secure_cookies=False,
                 metrics_token=None):

    class Handler(BaseHTTPRequestHandler):
        server_version = "mikromon"

        def log_message(self, *_):
            pass

        # ---- low-level helpers ----
        def _send(self, code, body, ctype="text/plain; charset=utf-8", headers=None):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _redirect(self, location, headers=None):
            self.send_response(303)
            self.send_header("Location", location)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _cookie_header(self, token, clear=False):
            attrs = f"{_COOKIE}={'' if clear else token}; HttpOnly; SameSite=Lax; Path=/"
            attrs += "; Max-Age=0" if clear else ""
            if secure_cookies:
                attrs += "; Secure"
            return {"Set-Cookie": attrs}

        def _token(self):
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            try:
                return SimpleCookie(raw)[_COOKIE].value
            except KeyError:
                return None

        def _session(self):
            return sessions.get(self._token())

        def _user(self):
            s = self._session()
            return auth.get_user(s["username"]) if s else None

        def _form(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8") if length else ""
            return {k: v[-1] for k, v in parse_qs(body, keep_blank_values=True).items()}, \
                   parse_qs(body, keep_blank_values=True)

        def _store(self):
            return MetricsStore(metrics_db)

        # ---- GET ----
        def do_GET(self):
            url = urlparse(self.path)
            path = url.path
            if path == "/health":
                return self._send(200, "ok")

            # No auth configured -> open dashboard (back-compat / demo without auth).
            if auth is None:
                return self._serve_data(path, url, user=None, allowed=None)

            if path == "/login":
                if self._session():
                    return self._redirect("/")
                err = {"1": "Invalid username or password."}.get(
                    parse_qs(url.query).get("error", [""])[0], "")
                return self._send(200, _render_login(err), "text/html; charset=utf-8")
            if path == "/logout":
                sessions.destroy(self._token())
                return self._redirect("/login", self._cookie_header("", clear=True))
            if path == "/metrics":
                return self._serve_metrics(url)

            user = self._user()
            if not user:
                if path.startswith("/api/"):
                    return self._send(401, '{"error":"unauthorized"}',
                                      "application/json")
                return self._redirect("/login")
            if path == "/admin":
                return self._serve_admin(user)

            store = self._store()
            allowed = AuthStore.allowed_devices(user, _known_devices(
                store, _load_state(state_file)))
            store.close()
            return self._serve_data(path, url, user=user, allowed=allowed)

        def _serve_data(self, path, url, user, allowed):
            store = self._store()
            try:
                state = _load_state(state_file)
                if path == "/":
                    return self._send(200, _render_dashboard(store, state, user,
                                      allowed), "text/html; charset=utf-8")
                if path == "/api/devices":
                    return self._send(200, json.dumps(
                        _all_devices(store, state, allowed), indent=2),
                        "application/json")
                if path == "/api/series":
                    q = parse_qs(url.query)
                    dev = q.get("device", [""])[0]
                    if allowed is not None and dev not in allowed:
                        return self._send(403, '{"error":"forbidden"}',
                                          "application/json")
                    rows = store.series(dev, q.get("metric", [""])[0],
                                        label=q.get("label", [""])[0],
                                        since=float(q.get("since",
                                                    [time.time() - 3600])[0]))
                    return self._send(200, json.dumps(
                        [{"ts": t, "value": v} for t, v in rows]),
                        "application/json")
                if path == "/metrics":  # only reached when auth is None
                    return self._send(200, _render_prometheus(store, allowed))
                return self._send(404, "not found")
            finally:
                store.close()

        def _serve_metrics(self, url):
            token = (parse_qs(url.query).get("token", [""])[0]
                     or self.headers.get("Authorization", "").removeprefix("Bearer "))
            ok = metrics_token and secrets.compare_digest(token, metrics_token)
            if not ok:
                user = self._user()
                if not AuthStore.is_admin(user or {}):
                    return self._send(401, "unauthorized\n",
                                      headers={"WWW-Authenticate": "Bearer"})
            store = self._store()
            try:
                return self._send(200, _render_prometheus(store, None))
            finally:
                store.close()

        def _serve_admin(self, user):
            if not AuthStore.is_admin(user):
                return self._send(403, "forbidden")
            store = self._store()
            known = _known_devices(store, _load_state(state_file))
            store.close()
            return self._send(200, _render_admin(
                auth, known, self._session()["csrf"], user),
                "text/html; charset=utf-8")

        # ---- POST ----
        def do_POST(self):
            if auth is None:
                return self._send(404, "not found")
            path = urlparse(self.path).path
            if path == "/login":
                return self._post_login()
            if path == "/logout":
                sessions.destroy(self._token())
                return self._redirect("/login", self._cookie_header("", clear=True))
            # Everything below requires an admin + a valid CSRF token.
            user = self._user()
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            flat, multi = self._form()
            if flat.get("csrf") != self._session()["csrf"]:
                return self._send(400, "bad csrf token")
            try:
                if path == "/admin/add":
                    auth.add_user(flat.get("username", ""), flat.get("password", ""),
                                  role=flat.get("role", "user"),
                                  devices=self._devices(flat, multi))
                elif path == "/admin/update":
                    auth.set_role(flat["username"], flat.get("role", "user"))
                    auth.set_devices(flat["username"], self._devices(flat, multi))
                elif path == "/admin/delete":
                    if flat["username"] == user["username"]:
                        return self._send(400, "cannot delete yourself")
                    auth.delete_user(flat["username"])
                else:
                    return self._send(404, "not found")
            except Exception as exc:  # noqa: BLE001 — surface as a simple message
                return self._send(400, f"Error: {exc}")
            return self._redirect("/admin")

        @staticmethod
        def _devices(flat, multi):
            if flat.get("all"):
                return "*"
            return multi.get("devices", [])

        def _post_login(self):
            flat, _ = self._form()
            user = auth.verify(flat.get("username", ""), flat.get("password", ""))
            if not user:
                time.sleep(0.5)  # mild brute-force friction
                return self._redirect("/login?error=1")
            token = sessions.create(user["username"])
            return self._redirect("/", self._cookie_header(token))

    return Handler


def serve(metrics_db, state_file, host="127.0.0.1", port=8080, auth_db=None,
          secure_cookies=False, metrics_token=None):
    if metrics_db and not os.path.exists(metrics_db):
        log.warning("metrics DB %s not found yet — start the monitor first",
                    metrics_db)
    auth = AuthStore(auth_db) if auth_db else None
    if auth and not auth.count_admins():
        log.warning("No admin users exist yet. Create one: "
                    "python -m mikromon useradd --user admin --password ... "
                    "--role admin -c <config>")
    sessions = SessionManager()
    httpd = ThreadingHTTPServer(
        (host, port), make_handler(metrics_db, state_file, auth, sessions,
                                   secure_cookies, metrics_token))
    scheme = "auth ON" if auth else "auth OFF (open)"
    log.info("Dashboard at http://%s:%d  [%s]  Prometheus: /metrics",
             host, port, scheme)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if auth:
            auth.close()
