#!/usr/bin/env python3
"""Turn a Zoho grant code into working API credentials, without retyping any
of them.

The values involved are a 30-odd character client id, a 42-character hex
secret and a two-part grant code, and the grant code expires in minutes and
is single-use. Copying those onto a server by hand, against a clock, is how
a character gets dropped -- and the error you get back for a mistyped secret
("invalid_client") is the same one you get for the wrong data centre, so you
cannot tell which mistake you made. That has cost time on this system before,
with a WireGuard key.

So: paste each value once, at a prompt, and this does the rest -- including
working out which data centre the account is on by simply trying both, and
proving the credentials work by reading the organisation back off the API.

  python3 tools/zoho_setup.py

Non-interactively:

  python3 tools/zoho_setup.py --client-id 1000.XXXX --client-secret abc123 \
      --code 1000.aaaa.bbbb

To mint a fresh access token later from the saved refresh token (the refresh
token itself never expires; access tokens last an hour):

  python3 tools/zoho_setup.py --refresh

Credentials are written to zoho-oauth.json next to config.yaml, mode 0600.
Nothing is printed in full: the file is the copy that matters.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

# The account lives in exactly one data centre, and every URL has to match it.
# Using the wrong one fails as "invalid_client", which reads like a bad secret
# -- so rather than asking anyone to know this, we try them.
_DCS = (
    ("accounts.zoho.com", "https://www.zohoapis.com/invoice/v3"),
    ("accounts.zoho.eu", "https://www.zohoapis.eu/invoice/v3"),
    ("accounts.zoho.in", "https://www.zohoapis.in/invoice/v3"),
    ("accounts.zoho.com.au", "https://www.zohoapis.com.au/invoice/v3"),
)

_SCOPES = ("ZohoInvoice.contacts.CREATE,ZohoInvoice.contacts.READ,"
           "ZohoInvoice.invoices.CREATE,ZohoInvoice.invoices.READ,"
           "ZohoInvoice.settings.READ")

_DEFAULT_CFGS = ("config.yaml", "/opt/mikromon/config.yaml",
                 "/etc/mikromon/config.yaml")


def _opt(name: str) -> str:
    """Read --name=value or --name value from argv. "" when absent."""
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == f"--{name}" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
    return ""


def _flag(name: str) -> bool:
    return f"--{name}" in sys.argv[1:]


def _creds_path() -> str:
    """Beside config.yaml, so it travels with the rest of the deployment."""
    explicit = _opt("out")
    if explicit:
        return explicit
    for c in _DEFAULT_CFGS:
        if os.path.exists(c):
            return os.path.join(os.path.dirname(os.path.abspath(c)),
                                "zoho-oauth.json")
    return os.path.abspath("zoho-oauth.json")


def _post(host: str, fields: dict) -> dict:
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(f"https://{host}/oauth/v2/token", data=body)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            return {"error": f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _get(api_base: str, path: str, token: str, org_id: str = "") -> dict:
    req = urllib.request.Request(api_base.rstrip("/") + path)
    req.add_header("Authorization", f"Zoho-oauthtoken {token}")
    if org_id:
        req.add_header("X-com-zoho-invoice-organizationid", org_id)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            return {"error": f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _save(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)      # 0600
    except OSError:
        pass
    os.replace(tmp, path)


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _mask(v: str) -> str:
    v = str(v or "")
    return f"{v[:10]}...{v[-6:]}  ({len(v)} chars)" if len(v) > 20 else v


def _ask(label: str, current: str = "") -> str:
    if current:
        return current
    try:
        return input(f"  {label}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(1)


def _refresh_access(host: str, cid: str, secret: str, refresh: str) -> dict:
    return _post(host, {"grant_type": "refresh_token",
                        "refresh_token": refresh,
                        "client_id": cid, "client_secret": secret})


def _verify(api_base: str, token: str) -> tuple:
    """Read the organisation back. This is the part that proves it works --
    a token that parses is not the same as a token the API accepts."""
    res = _get(api_base, "/organizations", token)
    orgs = res.get("organizations") or []
    if not orgs:
        return "", "", res.get("message") or res.get("error") or "no organisations returned"
    org = orgs[0]
    return str(org.get("organization_id", "")), str(org.get("name", "")), ""


def do_refresh() -> int:
    path = _creds_path()
    saved = _load(path)
    if not saved.get("refresh_token"):
        print(f"No saved credentials at {path}. Run without --refresh first.")
        return 1
    host = saved.get("accounts_host") or _DCS[0][0]
    res = _refresh_access(host, saved.get("client_id", ""),
                          saved.get("client_secret", ""),
                          saved["refresh_token"])
    if not res.get("access_token"):
        print(f"FAILED: {res.get('error') or res}")
        return 1
    saved["access_token"] = res["access_token"]
    _save(path, saved)
    org_id, org_name, err = _verify(saved.get("api_base", ""),
                                    res["access_token"])
    print(f"  access token  : {_mask(res['access_token'])}")
    if err:
        print(f"  WARNING: minted, but the API rejected it: {err}")
        return 1
    print(f"  verified against: {org_name} ({org_id})")
    return 0


def main() -> int:
    if _flag("help") or _flag("-h"):
        print(__doc__)
        return 0
    if _flag("refresh"):
        return do_refresh()

    path = _creds_path()
    saved = _load(path)

    print("\nZoho Invoice API setup")
    print("=" * 60)
    print("From https://api-console.zoho.com -> your Self Client.")
    print("Generate Code needs the scopes COMMA separated, no spaces:\n")
    print(f"  {_SCOPES}\n")
    print("The code is single-use and expires in minutes, so generate it")
    print("last -- right before running this.\n")

    cid = _ask("Client ID", _opt("client-id") or saved.get("client_id", ""))
    secret = _ask("Client Secret",
                  _opt("client-secret") or saved.get("client_secret", ""))
    code = _ask("Grant code", _opt("code"))
    if not (cid and secret and code):
        print("\nAll three are needed.")
        return 1

    forced = _opt("dc")
    dcs = [d for d in _DCS if not forced or d[0].endswith(forced)] or list(_DCS)

    print("\nExchanging...")
    last = {}
    for host, api_base in dcs:
        res = _post(host, {"grant_type": "authorization_code",
                           "client_id": cid, "client_secret": secret,
                           "code": code})
        if res.get("refresh_token"):
            print(f"  data centre   : {host}")
            print(f"  refresh token : {_mask(res['refresh_token'])}")

            org_id, org_name, err = _verify(api_base, res.get("access_token", ""))
            data = {"client_id": cid, "client_secret": secret,
                    "refresh_token": res["refresh_token"],
                    "access_token": res.get("access_token", ""),
                    "accounts_host": host, "api_base": api_base,
                    "organization_id": org_id, "organization_name": org_name,
                    "scopes": _SCOPES}
            _save(path, data)

            if err:
                print(f"  organisation  : COULD NOT READ -- {err}")
                print(f"\nSaved to {path} anyway, but something is not right:")
                print("the token was issued and the API would not accept it.")
                print("Usually a missing scope. Check ZohoInvoice.settings.READ")
                print("is in the list, generate a new code and run this again.")
                return 1

            print(f"  organisation  : {org_name} ({org_id})")
            print(f"\nSaved to {path} (mode 0600).")
            print("\nVerified end to end: the token was issued AND the API")
            print("answered with it. Nothing else needs copying anywhere.")
            return 0

        last = res
        err = str(res.get("error", ""))
        print(f"  {host}: {err or res}")
        # A bad or spent code fails identically everywhere -- trying the
        # other data centres only wastes the little time the code has left.
        if err == "invalid_code":
            break

    print("\nNo refresh token was issued.")
    err = str(last.get("error", ""))
    if err == "invalid_code":
        print("The code was already used, or it expired. They are single-use")
        print("and short-lived: generate a fresh one and run this again -- it")
        print("remembers the client id and secret, so it is one paste.")
    elif err == "invalid_client":
        print("Tried every data centre, so this is the client id or secret")
        print("rather than the region. Re-copy both from the API console.")
    elif "invalid_scope" in err:
        print("The scopes were rejected at code-generation time. They must be")
        print("COMMA separated with no spaces -- see the list above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
