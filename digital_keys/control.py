"""
digital_keys.control - the human-only control channel.

Two classes of caller talk to a running broker:

  * **agents** - they hold a short-lived capability token and may call
    ``/v1/request``. They never see the vault passphrase and never need
    anything from this module.

  * **the human** - ``dk grant``, ``dk stop``, ``dk audit``. These can mint
    capabilities, so they must prove they are the same person who started the
    broker.

The proof is transport-based wherever the kernel can provide it:

  POSIX with ``SO_PEERCRED``  a ``0600`` Unix socket under ``$XDG_RUNTIME_DIR``.
                              The kernel reports the connecting process's UID;
                              a different user cannot even connect, and a
                              same-UID process is by definition the operator.
                              No secret exists, so none can leak.

  Windows / no ``SO_PEERCRED``  TCP loopback plus a 32-byte bearer token read
                              from a ``0600`` file. ``SO_PEERCRED`` does not
                              exist there, so a token is the only option.

The TCP+token path is also the substrate for LAN/phone approval later, which is
why it is built now rather than bolted on afterwards.

Nothing here ever handles the vault passphrase.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import struct
import sys
from pathlib import Path

# 32 bytes of entropy -> 43 urlsafe characters.
TOKEN_BYTES = 32
TOKEN_ENV = "DIGITAL_KEYS_CONTROL_TOKEN"

_SO_PEERCRED_SIZE = struct.calcsize("3i")  # struct ucred { pid, uid, gid }


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def data_dir() -> Path:
    """The durable Digital Keys directory (holds the vault itself)."""
    override = os.environ.get("DIGITAL_KEYS_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / "digital-keys"


def runtime_dir() -> Path:
    """
    Where the control socket and token live.

    Prefer ``$XDG_RUNTIME_DIR``: it is created per-login, mode 0700, and wiped
    on logout, so a stale socket cannot outlive the session. Fall back to the
    data directory on systems that do not set it.
    """
    override = os.environ.get("DIGITAL_KEYS_RUNTIME_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg and os.path.isdir(xdg):
        return Path(xdg) / "digital-keys"
    return data_dir() / "run"


def socket_path() -> Path:
    return runtime_dir() / "control.sock"


def token_path() -> Path:
    return runtime_dir() / "control.token"


def port_path() -> Path:
    """
    The control port, when the broker is using the TCP control channel.

    A random ephemeral port is safer than a fixed one, but the CLI still has to
    find it. Publishing the port in the runtime directory keeps discovery local
    and removes the need for a hard-coded port that might collide.
    """
    return runtime_dir() / "control.port"


def _ensure_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir's mode is masked by the umask, so set it explicitly afterwards.
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


# --------------------------------------------------------------------------
# Capability probe
# --------------------------------------------------------------------------


def unix_control_supported() -> bool:
    """
    True when a Unix socket can carry a *verifiable* peer identity.

    ``AF_UNIX`` alone is not enough: Windows 10+ has it, but without
    ``SO_PEERCRED`` the server cannot tell who connected, so a socket would be
    no stronger than an unauthenticated TCP port. Require both.
    """
    return (
        os.name == "posix"
        and hasattr(socket, "AF_UNIX")
        and hasattr(socket, "SO_PEERCRED")
    )


def peer_uid(conn: socket.socket) -> int | None:
    """
    The UID at the far end of a connected Unix socket, or None if the platform
    cannot say. Callers must treat None as a failure, never as a pass.
    """
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _SO_PEERCRED_SIZE)
    except OSError:
        return None
    if len(raw) != _SO_PEERCRED_SIZE:
        return None
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


# --------------------------------------------------------------------------
# Bearer token (TCP control channel)
# --------------------------------------------------------------------------


def mint_token() -> str:
    """
    Create a fresh control token and write it 0600.

    The token is rotated on every ``dk serve``, so a token captured from a
    previous run is worthless. Written via a temp file + ``os.replace`` so a
    reader never observes a half-written token.
    """
    token = secrets.token_urlsafe(TOKEN_BYTES)
    path = token_path()
    _ensure_dir(path.parent)

    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("ascii"))
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    if not hasattr(os, "fchmod"):
        try:
            os.chmod(tmp, 0o600)  # Windows: best effort, only clears read-only
        except OSError:
            pass
    os.replace(tmp, path)
    return token


def load_token() -> str | None:
    """Read the current control token, or None if no broker has minted one."""
    env = os.environ.get(TOKEN_ENV)
    if env:
        return env.strip() or None
    try:
        return token_path().read_text(encoding="ascii").strip() or None
    except (OSError, UnicodeDecodeError):
        return None


def verify_token(supplied: str | None) -> bool:
    """
    Constant-time comparison against the active token.

    ``hmac.compare_digest`` rather than ``==`` so the comparison time does not
    depend on how many leading bytes matched.
    """
    expected = load_token()
    if not expected or not supplied:
        return False
    return hmac.compare_digest(supplied, expected)


def clear_token() -> None:
    try:
        token_path().unlink()
    except OSError:
        pass


def write_port(port: int) -> None:
    path = port_path()
    _ensure_dir(path.parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, str(int(port)).encode("ascii"))
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def read_port() -> int | None:
    try:
        return int(port_path().read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def clear_port() -> None:
    try:
        port_path().unlink()
    except OSError:
        pass


def clear_socket() -> None:
    try:
        socket_path().unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------
# Client side - used by the CLI
# --------------------------------------------------------------------------


class ControlUnavailable(RuntimeError):
    """No control channel could be reached."""


def control_request(
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    port: int | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict]:
    """
    Send one request over the control channel and return ``(status, body)``.

    Prefers the Unix socket when the platform supports a verifiable peer
    identity, because that keeps every privileged call - and the bearer token
    itself - off the TCP stack. Falls back to loopback TCP with the token, using
    the port the running broker published.

    Deliberately HTTP/1.0 with ``Connection: close``: one request per
    connection keeps the code small and avoids keep-alive state on a channel
    that is used a handful of times per session.
    """
    body = json.dumps(payload or {}).encode("utf-8")

    if unix_control_supported() and socket_path().exists():
        status, raw = _uds_request(method, path, body, timeout)
        return status, _parse(raw)

    token = load_token()
    if not token:
        raise ControlUnavailable(
            "no control token found - is a broker running? start one with 'dk serve'"
        )
    target = port or read_port()
    if not target:
        raise ControlUnavailable(
            "no control port found - is a broker running? start one with 'dk serve'"
        )
    return _tcp_request(method, path, body, token, target, timeout)


def _uds_request(method: str, path: str, body: bytes, timeout: float):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(str(socket_path()))
        head = (
            f"{method} {path} HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        conn.sendall(head + body)
        chunks = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        conn.close()
    return _split_http_response(b"".join(chunks))


def _tcp_request(method, path, body, token, port, timeout):
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body if method != "GET" else None,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, _parse(r.read())
    except urllib.error.HTTPError as exc:
        # 401/429 are meaningful answers, not transport failures.
        return exc.code, _parse(exc.read())


def _split_http_response(raw: bytes) -> tuple[int, bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise ControlUnavailable("empty response from control socket")
    try:
        status = int(lines[0].split(b" ")[1])
    except (IndexError, ValueError) as exc:
        raise ControlUnavailable("malformed status line from control socket") from exc
    return status, body


def _parse(raw: bytes) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"error": "unparseable response"}
    return data if isinstance(data, dict) else {"data": data}


def describe(mode: str = "auto") -> str:
    """A one-line summary for ``dk serve`` to print at startup."""
    if mode == "auto":
        mode = "unix" if unix_control_supported() else "tcp"
    if mode == "unix":
        return f"control: unix socket {socket_path()} (peer-UID verified)"
    port = read_port()
    where = f"127.0.0.1:{port}" if port else "127.0.0.1"
    return f"control: tcp {where} + bearer token ({token_path()})"


if __name__ == "__main__":  # pragma: no cover - manual probe
    print(f"python      : {sys.version.split()[0]}")
    print(f"unix+peercred: {unix_control_supported()}")
    print(f"runtime dir : {runtime_dir()}")
    print(f"socket      : {socket_path()} (exists={socket_path().exists()})")
    print(f"token       : {token_path()} (exists={token_path().exists()})")
