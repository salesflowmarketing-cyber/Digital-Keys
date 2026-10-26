"""
digital_keys.server - the local HTTP faces of the broker.

Two listeners, two trust levels. Keeping them physically separate is the whole
point: an agent that can reach the request path has no route at all to the
capability-minting path.

**Agent listener** (TCP loopback)
    GET  /v1/health       liveness, no auth, no secrets
    GET  /v1/providers    which providers exist, and which records can serve them
    POST /v1/request      the proxied call, gated by a short-lived capability

**Control listener** (Unix socket with peer-UID check, or TCP + bearer token)
    POST /v1/grant            mint a capability
    POST /v1/emergency-stop   revoke every outstanding grant
    GET  /v1/pending          outstanding grants, for the human UI
    GET  /v1/audit            redacted audit tail
    POST /v1/token/rotate     replace the TCP control token

Nothing in this file ever returns a secret in a response body.
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler

from . import control
from .broker import BrokerConfig, Denied, Dispatcher
from .ratelimit import RateLimiter, key_for_peer

MAX_REQUEST_BYTES = 16 * 1024 * 1024
LOOPBACK = ("127.0.0.1", "::1", "localhost")

AGENT_ROUTES = ("/v1/health", "/v1/providers", "/v1/request")
CONTROL_ROUTES = (
    "/v1/grant",
    "/v1/emergency-stop",
    "/v1/pending",
    "/v1/audit",
    "/v1/token/rotate",
)

# ``UnixStreamServer`` only exists where the interpreter was built with
# AF_UNIX. Resolve it once so this module still imports on a platform that
# cannot use it; the broker only selects the unix transport when SO_PEERCRED
# is available, which implies the socket family is present.
_UnixStreamServer = getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)


# --------------------------------------------------------------------------
# Shared plumbing
# --------------------------------------------------------------------------


class _BaseHandler(BaseHTTPRequestHandler):
    server_version = "digital-keys/2.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence stderr access logs; they can carry paths
        pass

    def _json(self, status: int, payload, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Lock down the browser side: this API should never be fetchable.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return {}
        if length > MAX_REQUEST_BYTES:
            raise Denied("request body too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise Denied("body must be valid JSON") from exc
        if not isinstance(data, dict):
            raise Denied("body must be a JSON object")
        return data

    # -- peer identity ----------------------------------------------------

    def _peer_uid(self) -> int | None:
        if getattr(self.server, "control_mode", None) == "unix":
            return control.peer_uid(self.connection)
        return None

    def _rate_key(self) -> str:
        return key_for_peer(self._peer_uid(), self.client_address)

    def _passphrase_key(self) -> str:
        """
        A separate counter for passphrase guesses.

        Transport auth and passphrase guesses must not share a bucket: a
        correct token would otherwise clear the guess counter on every attempt,
        which is exactly the hole this is meant to close.
        """
        return self._rate_key() + "|passphrase"

    def _bearer(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if not header:
            return None
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            return None
        return value.strip()


# --------------------------------------------------------------------------
# Agent listener
# --------------------------------------------------------------------------


class _AgentHandler(_BaseHandler):
    def do_GET(self):
        disp: Dispatcher = self.server.dispatcher  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path == "/v1/health":
            return self._json(200, {"ok": True, "service": "digital-keys-broker"})
        if path == "/v1/providers":
            return self._json(200, self._providers(disp))
        return self._json(404, {"error": "no such route"})

    def do_POST(self):
        disp: Dispatcher = self.server.dispatcher  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path != "/v1/request":
            # Control routes are not reachable from the agent listener at all.
            return self._json(404, {"error": "no such route"})

        if getattr(self.server, "lockdown", False) and not self._lockdown_ok():
            return self._json(
                401,
                {"error": "lockdown mode: a control credential is required on /v1/request"},
            )

        try:
            req = self._read_json()
            status, headers, payload = disp.handle_request(req)
            return self._json(status, payload)
        except Denied as exc:
            return self._json(400, {"error": str(exc)})
        except Exception:
            return self._json(500, {"error": "internal error"})

    def _lockdown_ok(self) -> bool:
        """
        Opt-in hardening: require the control credential *in addition to* the
        capability token on /v1/request.

        Off by default because it breaks the core promise - that an agent holds
        exactly one short-lived token and nothing else. Operators who want a
        second lock must hand every agent a long-lived secret.
        """
        limiter: RateLimiter = self.server.ratelimiter  # type: ignore[attr-defined]
        key = self._rate_key()
        if limiter.retry_after(key):
            return False
        if self.server.control_mode == "unix":  # type: ignore[attr-defined]
            uid = self._peer_uid()
            ok = uid is not None and uid == os.getuid()
        else:
            ok = control.verify_token(self._bearer())
        if not ok:
            limiter.fail(key)
        return ok

    def _providers(self, disp: Dispatcher):
        """
        List providers plus which record ids can serve each. This is
        deliberately metadata-only: an agent learns that "openrouter" exists
        and that record abc123 uses it, and nothing about the secret itself.
        """
        out = []
        try:
            with disp.vault.unlock(self.server.passphrase_fn()) as h:  # type: ignore[attr-defined]
                providers = h.providers()
                records = [r for r in h.records() if r.agent_capable]
        except Exception as exc:
            return {"error": "vault locked; approve access from the dk app", "detail": type(exc).__name__}

        for p in providers:
            out.append(
                {
                    "id": p.id,
                    "label": p.label,
                    "category": p.category.value,
                    "base_url": p.base_url,
                    "auth_style": p.auth_style,
                    "allowed_methods": p.allowed_methods,
                    "allowed_path_prefixes": p.allowed_path_prefixes,
                    "records": [
                        {"id": r.id, "label": r.label, "username": r.username}
                        for r in records
                        if r.provider_id == p.id
                    ],
                }
            )
        return {"providers": out}


# --------------------------------------------------------------------------
# Control listener
# --------------------------------------------------------------------------


class _ControlHandler(_BaseHandler):
    """
    The privileged surface. Every route here requires a verified caller.
    """

    def _authorise(self) -> tuple[bool, dict | None]:
        """
        Returns (ok, error_payload).

        A rate-limited caller is rejected before any credential is examined, so
        a lockout cannot be used as an oracle.
        """
        limiter: RateLimiter = self.server.ratelimiter  # type: ignore[attr-defined]
        key = self._rate_key()

        # A passphrase lockout applies to the caller as a whole, not just to
        # /v1/grant: once someone is visibly guessing, stop answering them.
        for candidate in (key, self._passphrase_key()):
            wait = limiter.retry_after(candidate)
            if wait is not None:
                return False, {
                    "error": "too many failed attempts",
                    "retry_after": wait,
                }

        if self.server.control_mode == "unix":  # type: ignore[attr-defined]
            uid = self._peer_uid()
            if uid is None or uid != os.getuid():
                limiter.fail(key)
                return False, {"error": "control channel is not available to this user"}
            limiter.succeed(key)
            return True, None

        if not control.verify_token(self._bearer()):
            limiter.fail(key)
            return False, {"error": "control token required"}
        limiter.succeed(key)
        return True, None

    def _guard(self) -> bool:
        ok, err = self._authorise()
        if ok:
            return True
        assert err is not None
        status = 429 if "retry_after" in err else 401
        headers = {"Retry-After": err["retry_after"]} if "retry_after" in err else None
        self._json(status, err, headers)
        return False

    def do_GET(self):
        disp: Dispatcher = self.server.dispatcher  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path not in CONTROL_ROUTES:
            return self._json(404, {"error": "no such route"})
        if not self._guard():
            return
        if path == "/v1/pending":
            return self._json(200, {"grants": disp.caps.outstanding()})
        if path == "/v1/audit":
            n = 200
            if "?" in self.path:
                from urllib.parse import parse_qs, urlsplit

                q = parse_qs(urlsplit(self.path).query)
                n = int(q.get("limit", [200])[0])
            return self._json(200, {"audit": disp.audit.redacted(limit=n)})
        return self._json(405, {"error": "method not allowed"})

    def do_POST(self):
        disp: Dispatcher = self.server.dispatcher  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path not in CONTROL_ROUTES:
            return self._json(404, {"error": "no such route"})
        if not self._guard():
            return
        try:
            if path == "/v1/grant":
                return self._grant(disp)
            if path == "/v1/emergency-stop":
                n = disp.emergency_stop()
                return self._json(200, {"revoked": n})
            if path == "/v1/token/rotate":
                token = control.mint_token()
                return self._json(200, {"rotated": True, "token": token})
        except Denied as exc:
            return self._json(400, {"error": str(exc)})
        except Exception:
            return self._json(500, {"error": "internal error"})
        return self._json(405, {"error": "method not allowed"})

    def _grant(self, disp: Dispatcher):
        """
        Mint a capability. The caller already proved it is the operator, so the
        passphrase here is a second factor over the vault itself, not the
        authorisation for this route.
        """
        limiter: RateLimiter = self.server.ratelimiter  # type: ignore[attr-defined]
        key = self._passphrase_key()

        data = self._read_json()
        passphrase = data.get("passphrase") or ""
        if not passphrase:
            limiter.fail(key)
            return self._json(401, {"error": "passphrase required"})
        try:
            with disp.vault.unlock(passphrase) as h:
                rec = h.get(data["record_id"])
                provider_id = data.get("provider_id") or rec.provider_id
                if not provider_id:
                    return self._json(400, {"error": "record has no provider"})
                h.provider(provider_id)  # existence check
        except KeyError as exc:
            return self._json(404, {"error": str(exc)})
        except Exception:
            # Wrong passphrase: count it, and never echo the exception text.
            lockout = limiter.fail(key)
            payload = {"error": "could not unlock vault"}
            if lockout is not None:
                payload["retry_after"] = int(lockout)
                return self._json(429, payload, {"Retry-After": int(lockout)})
            return self._json(401, payload)

        limiter.succeed(key)
        cap = disp.grant(
            data["record_id"],
            provider_id,
            methods=data.get("methods") or ["GET", "POST"],
            path_prefix=data.get("path_prefix", "/"),
            ttl=data.get("ttl", 300.0),
            label=data.get("label", ""),
            single_use=bool(data.get("single_use", True)),
        )
        return self._json(200, {
            "token": cap.token_id,
            "record_id": cap.record_id,
            "provider_id": cap.provider_id,
            "methods": list(cap.methods),
            "path_prefix": cap.path_prefix,
            "expires_in": round(cap.expires_at - cap.issued_at, 1),
            "single_use": cap.single_use,
        })


# --------------------------------------------------------------------------
# Listeners
# --------------------------------------------------------------------------


class VaultServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """The agent-facing listener. Serves request/providers/health only."""

    daemon_threads = True
    allow_reuse_address = True
    control_mode = "tcp"

    def __init__(
        self,
        config: BrokerConfig,
        passphrase_fn,
        host="127.0.0.1",
        port=0,
        *,
        dispatcher: Dispatcher | None = None,
        ratelimiter: RateLimiter | None = None,
        lockdown: bool = False,
    ):
        if host not in LOOPBACK and not config.allow_private_for_custom:
            raise Denied(
                f"refusing to bind dk to {host}: the broker is a local-only service. "
                "Exposing it would let anyone on the network request your credentials."
            )
        self.dispatcher = dispatcher or Dispatcher(config)
        self.passphrase_fn = passphrase_fn
        self.ratelimiter = ratelimiter or RateLimiter()
        self.lockdown = lockdown
        super().__init__((host, port), _AgentHandler)

    @property
    def port(self) -> int:
        return self.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class UnixControlServer(socketserver.ThreadingMixIn, _UnixStreamServer):
    """
    Control listener on a 0600 Unix socket.

    The socket's own mode stops other users from connecting; ``SO_PEERCRED``
    then confirms the UID of whoever did connect, so a compromised or confused
    path cannot widen access.

    Only defined where ``socketserver`` exposes ``UnixStreamServer``. Windows
    has ``AF_UNIX`` on recent builds but never uses this path, because the
    broker only selects it when ``SO_PEERCRED`` exists.
    """

    daemon_threads = True
    control_mode = "unix"

    def __init__(self, path, dispatcher: Dispatcher, ratelimiter: RateLimiter, passphrase_fn):
        self.dispatcher = dispatcher
        self.ratelimiter = ratelimiter
        self.passphrase_fn = passphrase_fn
        self.lockdown = False
        self.path = str(path)
        _unlink(self.path)
        super().__init__(self.path, _ControlHandler)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @property
    def base_url(self) -> str:
        return f"unix:{self.path}"

    def server_close(self):
        super().server_close()
        _unlink(self.path)


class TCPControlServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Control listener for platforms without SO_PEERCRED, and for LAN later."""

    daemon_threads = True
    allow_reuse_address = True
    control_mode = "tcp"

    def __init__(self, dispatcher: Dispatcher, ratelimiter: RateLimiter, passphrase_fn, host, port):
        self.dispatcher = dispatcher
        self.ratelimiter = ratelimiter
        self.passphrase_fn = passphrase_fn
        self.lockdown = False
        super().__init__((host, port), _ControlHandler)

    @property
    def port(self) -> int:
        return self.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


class BrokerRuntime:
    """
    Everything a running broker owns: one Dispatcher shared by both listeners,
    the rate limiter, and the control credential.
    """

    def __init__(
        self,
        config: BrokerConfig,
        passphrase_fn,
        host="127.0.0.1",
        port=0,
        *,
        control_transport: str = "auto",
        lockdown: bool = False,
    ):
        self.dispatcher = Dispatcher(config)
        self.ratelimiter = RateLimiter()
        self.token = None
        self.agent = VaultServer(
            config,
            passphrase_fn,
            host=host,
            port=port,
            dispatcher=self.dispatcher,
            ratelimiter=self.ratelimiter,
            lockdown=lockdown,
        )
        self.control = None
        self.control_mode = None
        self._threads: list[threading.Thread] = []

        # Lockdown authenticates agents with a bearer token, which needs a token
        # to exist even when the control channel itself is a Unix socket.
        if lockdown:
            self.token = control.mint_token()

        want = control_transport
        if want == "auto":
            want = "unix" if control.unix_control_supported() else "tcp"

        if want == "unix":
            if not control.unix_control_supported():
                self.agent.server_close()
                raise Denied(
                    "unix control transport requested but this platform has no "
                    "SO_PEERCRED; use --control-transport tcp"
                )
            path = control.socket_path()
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            control.clear_port()  # drop any stale TCP control port from a previous run
            self.control = UnixControlServer(path, self.dispatcher, self.ratelimiter, passphrase_fn)
            self.control_mode = "unix"
        elif want == "tcp":
            self.token = control.mint_token()
            self.control = TCPControlServer(
                self.dispatcher, self.ratelimiter, passphrase_fn, "127.0.0.1", 0
            )
            control.write_port(self.control.port)
            self.control_mode = "tcp"
        else:
            self.agent.server_close()
            raise Denied(f"unknown control transport {want!r} (use auto, unix, or tcp)")

    # -- accessors --------------------------------------------------------

    @property
    def agent_url(self) -> str:
        return self.agent.base_url

    @property
    def port(self) -> int:
        return self.agent.port

    # -- lifecycle --------------------------------------------------------

    def start(self) -> "BrokerRuntime":
        for srv in (self.agent, self.control):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def stop(self) -> None:
        for srv in (self.control, self.agent):
            if srv is None:
                continue
            try:
                srv.shutdown()
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass
        self.ratelimiter = RateLimiter()
        if self.token is not None:
            control.clear_token()
        if self.control_mode == "tcp":
            control.clear_port()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def start_broker(
    config: BrokerConfig,
    passphrase_fn,
    port=0,
    *,
    control_transport: str = "auto",
    lockdown: bool = False,
) -> BrokerRuntime:
    """Convenience helper for tests and embedders."""
    return BrokerRuntime(
        config,
        passphrase_fn,
        port=port,
        control_transport=control_transport,
        lockdown=lockdown,
    ).start()


def serve_forever_in_thread(config: BrokerConfig, passphrase_fn, port=0):
    srv = VaultServer(config, passphrase_fn, port=port)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


__all__ = [
    "AGENT_ROUTES",
    "CONTROL_ROUTES",
    "BrokerRuntime",
    "TCPControlServer",
    "UnixControlServer",
    "VaultServer",
    "serve_forever_in_thread",
    "start_broker",
]
