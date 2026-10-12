"""Off-site backups: every night, encrypted, and somewhere that is not here.

A backup kept on the server it backs up is lost with it. This one is built
every night by a systemd timer (deploy/install.sh), encrypted, and uploaded
to S3-compatible storage -- Amazon S3, or Backblaze B2 / Cloudflare R2 with
an endpoint set.

What goes in: every data file the server backup takes (databases, config,
tunnel registry), the secrets key the databases' sealed values need
(vault.py), and the hub's WireGuard private key -- which every router dials
home to, and without which every router would need setting up again by hand.
systemd hands that key to this job read-only (LoadCredential=), so it runs
as the service user and never touches the databases as root.

Encryption is age (https://age-encryption.org/v1), X25519: the server holds
only the PUBLIC key. The private one is shown once, when it is made, for the
person to keep off this server -- so neither someone who copies the bucket
nor someone who takes the server can open a backup. Restoring needs the
private key, and the standard `age` tool opens these files anywhere:
    age -d -i key.txt backup.tar.gz.age > backup.tar.gz
or, on a rebuilt server:
    sudo .venv/bin/python -m mikromon restore-server -c config.yaml \\
        --archive backup.tar.gz.age --identity key.txt --apply

The upload key should only be allowed to ADD objects (s3:PutObject), and the
bucket should keep old versions and expire them by rule: then even someone
who takes the server cannot delete or overwrite the backups.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

STATUS_NAME = "offsite-status.json"
TRIGGER_NAME = "offsite-run-now"
CREDENTIAL = "hub-wg-key"           # systemd LoadCredential name
WG_KEY_PATH = "/etc/wireguard/wg0.key"

# ---------------------------------------------------------------------------
# bech32 (BIP 173), for age's key encodings
# ---------------------------------------------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values) -> int:
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frm: int, to: int, pad: bool = True) -> list:
    acc = bits = 0
    out = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to - bits)) & maxv)
    elif not pad and (bits >= frm or ((acc << (to - bits)) & maxv)):
        raise ValueError("invalid padding")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    hrp = hrp.lower()
    words = _convertbits(data, 8, 5)
    poly = _polymod(_hrp_expand(hrp) + words + [0] * 6) ^ 1
    check = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[w] for w in words + check)


def bech32_decode(text: str) -> tuple:
    s = text.strip()
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or len(s) - pos < 7:
        raise ValueError("not bech32")
    hrp = s[:pos]
    try:
        words = [_CHARSET.index(c) for c in s[pos + 1:]]
    except ValueError:
        raise ValueError("not bech32") from None
    if _polymod(_hrp_expand(hrp) + words) != 1:
        raise ValueError("bad checksum")
    return hrp, bytes(_convertbits(words[:-6], 5, 8, pad=False))


# ---------------------------------------------------------------------------
# age v1, X25519 recipients
# ---------------------------------------------------------------------------
_INTRO = b"age-encryption.org/v1\n"
_CHUNK = 64 * 1024


def _crypto():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return (hashes, serialization, X25519PrivateKey, X25519PublicKey,
            ChaCha20Poly1305, HKDF)


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    hashes, _s, _p, _q, _c, HKDF = _crypto()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=info).derive(ikm)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def generate_identity() -> tuple:
    """A new key pair: (private "AGE-SECRET-KEY-1...", public "age1...")."""
    _h, ser, Priv, _Pub, _c, _k = _crypto()
    sk = Priv.generate()
    raw_sk = sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw,
                              ser.NoEncryption())
    raw_pk = sk.public_key().public_bytes(ser.Encoding.Raw,
                                          ser.PublicFormat.Raw)
    return (bech32_encode("age-secret-key-", raw_sk).upper(),
            bech32_encode("age", raw_pk))


def parse_recipient(text: str) -> bytes:
    hrp, raw = bech32_decode(text or "")
    if hrp != "age" or len(raw) != 32:
        raise ValueError("not an age public key (it starts with age1)")
    return raw


def parse_identity(text: str) -> bytes:
    for line in (text or "").splitlines():
        line = line.strip()
        if line.upper().startswith("AGE-SECRET-KEY-1"):
            hrp, raw = bech32_decode(line)
            if hrp == "age-secret-key-" and len(raw) == 32:
                return raw
    raise ValueError("no age private key (AGE-SECRET-KEY-1...) found")


def recipient_of(identity_text: str) -> str:
    _h, ser, Priv, _Pub, _c, _k = _crypto()
    sk = Priv.from_private_bytes(parse_identity(identity_text))
    return bech32_encode("age", sk.public_key().public_bytes(
        ser.Encoding.Raw, ser.PublicFormat.Raw))


def encrypt_file(src: str, dst: str, recipient: str) -> None:
    """Encrypt `src` to `dst` for one X25519 recipient, in age v1 format."""
    _h, ser, Priv, Pub, ChaCha, _k = _crypto()
    their = parse_recipient(recipient)
    file_key = os.urandom(16)
    eph = Priv.generate()
    share = eph.public_key().public_bytes(ser.Encoding.Raw,
                                          ser.PublicFormat.Raw)
    shared = eph.exchange(Pub.from_public_bytes(their))
    wrap = _hkdf(shared, share + their, b"age-encryption.org/v1/X25519")
    body = ChaCha(wrap).encrypt(b"\x00" * 12, file_key, None)
    b = _b64(body)
    lines = [b[i:i + 64] for i in range(0, len(b), 64)] or [""]
    if len(lines[-1]) == 64:
        lines.append("")
    header = (_INTRO + f"-> X25519 {_b64(share)}\n".encode()
              + "\n".join(lines).encode() + b"\n---")
    mac = hmac.new(_hkdf(file_key, b"", b"header"), header,
                   hashlib.sha256).digest()
    nonce = os.urandom(16)
    box = ChaCha(_hkdf(file_key, nonce, b"payload"))
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(header + b" " + _b64(mac).encode() + b"\n" + nonce)
        counter = 0
        chunk = fin.read(_CHUNK)
        while True:
            nxt = fin.read(_CHUNK) if len(chunk) == _CHUNK else b""
            last = not nxt
            n = counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
            fout.write(box.encrypt(n, chunk, None))
            if last:
                break
            chunk, counter = nxt, counter + 1


def decrypt_file(src: str, dst: str, identity_text: str) -> None:
    """Open an age v1 file made for this identity's X25519 public key."""
    _h, ser, Priv, Pub, ChaCha, _k = _crypto()
    sk = Priv.from_private_bytes(parse_identity(identity_text))
    mine = sk.public_key().public_bytes(ser.Encoding.Raw,
                                        ser.PublicFormat.Raw)
    with open(src, "rb") as fin:
        if fin.readline() != _INTRO:
            raise ValueError("not an age file")
        header = _INTRO
        file_key = None
        while True:
            line = fin.readline()
            if line.startswith(b"---"):
                header += b"---"
                mac = _unb64(line[4:].strip().decode())
                break
            if not line.startswith(b"-> "):
                raise ValueError("malformed age header")
            header += line
            args = line[3:].strip().decode().split(" ")
            body_lines = []
            while True:
                bl = fin.readline()
                header += bl
                body_lines.append(bl.strip().decode())
                if len(bl.strip()) < 64:
                    break
            if args[0] != "X25519" or file_key is not None:
                continue
            share = _unb64(args[1])
            shared = sk.exchange(Pub.from_public_bytes(share))
            wrap = _hkdf(shared, share + mine, b"age-encryption.org/v1/X25519")
            try:
                file_key = ChaCha(wrap).decrypt(
                    b"\x00" * 12, _unb64("".join(body_lines)), None)
            except Exception:  # noqa: BLE001 - another recipient's stanza
                file_key = None
        if file_key is None:
            raise ValueError("this key cannot open this backup")
        want = hmac.new(_hkdf(file_key, b"", b"header"), header,
                        hashlib.sha256).digest()
        if not hmac.compare_digest(want, mac):
            raise ValueError("the backup's header has been altered")
        nonce = fin.read(16)
        box = ChaCha(_hkdf(file_key, nonce, b"payload"))
        with open(dst, "wb") as fout:
            counter = 0
            block = fin.read(_CHUNK + 16)
            while True:
                nxt = fin.read(_CHUNK + 16)
                last = not nxt
                n = counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
                fout.write(box.decrypt(n, block, None))
                if last:
                    break
                block, counter = nxt, counter + 1


# ---------------------------------------------------------------------------
# S3 (AWS Signature Version 4), stdlib only
# ---------------------------------------------------------------------------
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign_v4(method, host, uri, query, headers, payload_hash, region,
            access_key, secret_key, amz_date, service="s3") -> str:
    """The Authorization header for one request. `headers` are the ones to
    sign (lower-case names); they must include host, x-amz-date and
    x-amz-content-sha256."""
    names = sorted(headers)
    canonical = "\n".join([
        method, uri, query,
        "".join(f"{n}:{' '.join(str(headers[n]).split())}\n" for n in names),
        ";".join(names), payload_hash])
    day = amz_date[:8]
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(("AWS4" + secret_key).encode(), day)
    k = _hmac(_hmac(_hmac(k, region), service), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={';'.join(names)}, Signature={sig}")


def _target(s: dict, key: str) -> tuple:
    """(url, host, canonical uri) for an object, virtual-hosted on AWS
    (path-style for a bucket name with dots), path-style on an endpoint."""
    bucket = s["bucket"].strip()
    region = (s.get("region") or "us-east-1").strip()
    path = "/" + "/".join(urllib.parse.quote(p, safe="-_.~")
                          for p in key.split("/"))
    endpoint = (s.get("endpoint") or "").strip().rstrip("/")
    if endpoint:
        if "://" not in endpoint:
            endpoint = "https://" + endpoint
        host = urllib.parse.urlparse(endpoint).netloc
        uri = "/" + urllib.parse.quote(bucket, safe="-_.~") + path
        return endpoint + uri, host, uri
    if "." in bucket:
        host = f"s3.{region}.amazonaws.com"
        uri = "/" + bucket + path
        return f"https://{host}{uri}", host, uri
    host = f"{bucket}.s3.{region}.amazonaws.com"
    return f"https://{host}{path}", host, path


def s3_put(s: dict, key: str, path: str, content_type: str,
           timeout: float = 600.0) -> None:
    """Upload one file. Raises RuntimeError saying what to fix."""
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            sha.update(block)
    payload_hash = sha.hexdigest()
    url, host, uri = _target(s, key)
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ")
    signed = {"host": host, "x-amz-content-sha256": payload_hash,
              "x-amz-date": amz_date}
    auth = sign_v4("PUT", host, uri, "", signed, payload_hash,
                   (s.get("region") or "us-east-1").strip(),
                   s["access_key"].strip(), s["secret_key"].strip(), amz_date)
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        req = urllib.request.Request(url, data=fh, method="PUT", headers={
            "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date,
            "Authorization": auth, "Content-Type": content_type,
            "Content-Length": str(size)})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                r.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            code = (body.split("<Code>")[1].split("</Code>")[0]
                    if "<Code>" in body else str(exc.code))
            hints = {
                "AccessDenied": "the key is not allowed to upload there -- "
                                "check its policy allows s3:PutObject on "
                                "this bucket and folder",
                "InvalidAccessKeyId": "the access key ID is wrong",
                "SignatureDoesNotMatch": "the secret key is wrong",
                "NoSuchBucket": "there is no bucket by that name",
                "PermanentRedirect": "the bucket is in another region",
                "AuthorizationHeaderMalformed": "the region is wrong for "
                                                "this bucket",
            }
            raise RuntimeError(f"upload refused ({code}): "
                               f"{hints.get(code, 'see the storage provider')}"
                               ) from None
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"could not reach the storage: {exc}") from None


def settings_problem(s: dict) -> str:
    """What is missing before backups can run; "" when nothing."""
    for field, label in (("bucket", "the bucket name"),
                         ("access_key", "the access key ID"),
                         ("secret_key", "the secret access key"),
                         ("recipient", "an encryption key")):
        if not (s or {}).get(field):
            return f"Set {label} first."
    try:
        parse_recipient(s["recipient"])
    except ValueError as exc:
        return f"The encryption key is not valid: {exc}."
    return ""


def test_upload(s: dict) -> str:
    """Upload a small file, to prove the storage settings. "" when it
    worked. (The encryption key is not needed for this.)"""
    for field, label in (("bucket", "the bucket name"),
                         ("access_key", "the access key ID"),
                         ("secret_key", "the secret access key")):
        if not (s or {}).get(field):
            return f"Set {label} first."
    fd, tmp = tempfile.mkstemp(prefix="offsite-test-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(f"EasyMikroTik off-site backup test from "
                     f"{socket.gethostname()} at "
                     f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        s3_put(s, _prefix(s) + "connection-test.txt", tmp, "text/plain",
               timeout=60)
        return ""
    except RuntimeError as exc:
        return str(exc)
    finally:
        os.unlink(tmp)


def _prefix(s: dict) -> str:
    p = (s.get("prefix") or "easymikrotik").strip().strip("/")
    return p + "/" if p else ""


# ---------------------------------------------------------------------------
# the nightly job
# ---------------------------------------------------------------------------
def data_dir(config) -> str:
    return os.path.dirname(os.path.abspath(config.devices_db or config.auth_db
                                           or "."))


def read_status(directory: str) -> dict:
    try:
        with open(os.path.join(directory, STATUS_NAME)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def request_run(directory: str) -> None:
    """Ask for a backup now: systemd's mikromon-offsite.path watches for
    this file and starts the job, which removes it."""
    with open(os.path.join(directory, TRIGGER_NAME), "w") as fh:
        fh.write(str(time.time()))


def _write_status(directory: str, status: dict) -> None:
    path = os.path.join(directory, STATUS_NAME)
    tmp = path + ".new"
    with open(tmp, "w") as fh:
        json.dump(status, fh)
    os.replace(tmp, path)


def archive_paths(config, config_path: str, cred_dir: str = "") -> dict:
    """Archive name -> file: the server backup's files, the secrets keys and
    the hub's WireGuard key."""
    from .backup import backup_paths
    paths = backup_paths(
        config_path=config_path, auth_db=config.auth_db,
        devices_db=config.devices_db, metrics_db=config.metrics_db,
        push_log_db=config.push_log_db,
        billing_db=(config.billing or {}).get("db"),
        state_file=config.state_file,
        access_grants_file=(config.access or {}).get("grants_file"),
        alert_log_db=config.alert_log_db)
    paths.update(key_paths(config))
    wg = os.path.join(cred_dir, CREDENTIAL) if cred_dir else WG_KEY_PATH
    if os.path.isfile(wg) and os.access(wg, os.R_OK):
        paths["system/wireguard/wg0.key"] = wg
    return paths


def key_paths(config) -> dict:
    """The secrets key of each data directory, as named in the archive."""
    from . import vault
    out, seen = {}, []
    for db in (config.auth_db, config.devices_db):
        if not db:
            continue
        d = os.path.dirname(os.path.abspath(db))
        if d in seen:
            continue
        seen.append(d)
        name = "secrets.key" if len(seen) == 1 else f"secrets-{len(seen)}.key"
        out[name] = vault.key_path(d)
    return out


def run(config, config_path: str, *, now: float | None = None,
        cred_dir: str | None = None) -> dict:
    """Build, encrypt and upload one backup; record how it went. Never
    raises: a failure is recorded, and emailed to the superadmins."""
    from .auth import AuthStore
    from .backup import build_archive_to_file
    now = now if now is not None else time.time()
    directory = data_dir(config)
    try:
        os.unlink(os.path.join(directory, TRIGGER_NAME))
    except OSError:
        pass
    auth = AuthStore(config.auth_db) if config.auth_db else None
    s = (auth.get_setting("offsite") if auth else None) or {}
    if not s.get("enabled"):
        # Nothing to do -- and nothing to record: a switched-off run is not
        # a failure, and must not show as one beside the last real result.
        if auth:
            auth.close()
        return {"ok": False, "error": "Off-site backups are switched off."}
    status = read_status(directory)
    status.update(last_run=now, ok=False, error="")
    try:
        problem = settings_problem(s)
        if problem:
            raise RuntimeError(problem)
        cred = cred_dir if cred_dir is not None else os.environ.get(
            "CREDENTIALS_DIRECTORY", "")
        paths = archive_paths(config, config_path, cred)
        work = os.path.join(directory, "backups-server")
        os.makedirs(work, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(now))
        plain = os.path.join(work, f".offsite-{stamp}.tar.gz")
        sealed = plain + ".age"
        try:
            skipped = build_archive_to_file(paths, plain)
            encrypt_file(plain, sealed, s["recipient"])
            day = time.strftime("%Y/%m/%d", time.gmtime(now))
            key = f"{_prefix(s)}{day}/easymikrotik-{stamp}.tar.gz.age"
            s3_put(s, key, sealed, "application/octet-stream")
            size = os.path.getsize(sealed)
        finally:
            for p in (plain, sealed):
                if os.path.exists(p):
                    os.unlink(p)
        status.update(
            ok=True, last_ok=now, object=key, size=size,
            wireguard="system/wireguard/wg0.key" in paths,
            skipped=[n for n, _e in skipped])
        log.info("off-site backup uploaded: %s (%d bytes)", key, size)
    except Exception as exc:  # noqa: BLE001 - recorded and emailed below
        status.update(ok=False, error=str(exc))
        log.error("off-site backup failed: %s", exc)
        _email_failure(auth, config, str(exc))
    finally:
        try:
            _write_status(directory, status)
        except OSError:
            log.exception("could not record the off-site backup status")
        if auth:
            auth.close()
    return status


def _email_failure(auth, config, error: str) -> None:
    if auth is None:
        return
    try:
        from email.message import EmailMessage

        from .notify.org_email import _smtp_send, effective_smtp
        smtp = effective_smtp(auth, config.smtp)
        to = auth.superadmin_emails()
        if not (smtp and getattr(smtp, "host", "") and to):
            return
        msg = EmailMessage()
        msg["Subject"] = (f"{smtp.subject_prefix} Off-site backup FAILED "
                          f"on {socket.gethostname()}").strip()
        msg["From"] = smtp.from_addr
        msg["To"] = ", ".join(to)
        msg.set_content(
            f"Tonight's off-site backup did not reach the storage:\n\n"
            f"  {error}\n\nUntil this is fixed, the newest copy off this "
            f"server is the last one that worked (Platform admin > Off-site "
            f"backups shows when that was).\n")
        _smtp_send(smtp, msg)
    except Exception:  # noqa: BLE001
        log.exception("could not email the off-site backup failure")
