"""Secrets kept encrypted at rest.

Router logins (full admin on every customer router), the mail-server
password, the payment and AI keys -- stored in plain text, a copied
database or a leaked backup would have handed over every customer's
network. They are sealed with AES-256-GCM under a key kept in its own file,
`secrets.key`, next to the databases, and opened only when used.

The key is not in the databases and not in the plain on-server backups, so
those leak nothing on their own. It IS in the off-site backup, which is
itself encrypted with a key that never touches this server (offsite.py) --
losing it would mean re-provisioning every router by hand.

Sealed values read "enc1:<base64 nonce+ciphertext>". Anything else is taken
as an old plain value and returned unchanged, so a database written before
this existed keeps working until the stores re-seal it on open.
"""
from __future__ import annotations

import base64
import logging
import os
import threading
import time

log = logging.getLogger(__name__)

PREFIX = "enc1:"
KEY_NAME = "secrets.key"
_AAD = b"mikromon-secret"

_cache: dict = {}
_lock = threading.Lock()


def key_path(directory: str) -> str:
    return os.path.join(directory or ".", KEY_NAME)


def _read(path: str) -> bytes:
    for _ in range(20):
        with open(path, "rb") as fh:
            raw = fh.read().strip()
        if raw:
            key = base64.b64decode(raw)
            if len(key) != 32:
                raise ValueError(f"{path} does not hold a 32-byte key")
            return key
        time.sleep(0.05)       # another process is writing it this moment
    raise ValueError(f"{path} is empty")


def load_key(directory: str) -> bytes:
    """The key for this data directory, created on first use (mode 0600).
    Created by writing a temp file and linking it into place, so two
    processes starting together cannot each make a different key."""
    path = os.path.abspath(key_path(directory))
    with _lock:
        if path in _cache:
            return _cache[path]
        if not os.path.exists(path):
            tmp = f"{path}.{os.getpid()}.{time.time_ns()}.new"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(base64.b64encode(os.urandom(32)) + b"\n")
            try:
                os.link(tmp, path)
                log.info("created the secrets key %s -- keep it: the "
                         "off-site backup carries it", path)
            except FileExistsError:
                pass
            finally:
                os.unlink(tmp)
        key = _read(path)
        _cache[path] = key
        return key


def _aead(directory: str):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    return AESGCM(load_key(directory))


def is_sealed(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def seal(value, directory: str):
    """`value` sealed for storage. Empty values and already-sealed ones are
    returned as they are."""
    if not isinstance(value, str) or not value or is_sealed(value):
        return value
    box = _aead(directory)
    if box is None:
        log.warning("the 'cryptography' package is missing, so a secret is "
                    "being stored unencrypted -- run deploy/install.sh")
        return value
    nonce = os.urandom(12)
    return PREFIX + base64.b64encode(
        nonce + box.encrypt(nonce, value.encode("utf-8"), _AAD)).decode()


def unseal(value, directory: str):
    """The plain value of something `seal` stored; anything not sealed is
    returned unchanged. A value that cannot be opened -- the wrong key file,
    say, after restoring a database without its key -- comes back as ""
    and is logged, rather than crashing whatever needed it."""
    if not is_sealed(value):
        return value
    box = _aead(directory)
    try:
        raw = base64.b64decode(value[len(PREFIX):])
        if box is None:
            raise RuntimeError("the 'cryptography' package is missing")
        return box.decrypt(raw[:12], raw[12:], _AAD).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        log.error("could not open a stored secret (%s). The secrets key at "
                  "%s does not match the one it was sealed with -- restore "
                  "the matching secrets.key from the off-site backup.",
                  exc, key_path(directory))
        return ""
