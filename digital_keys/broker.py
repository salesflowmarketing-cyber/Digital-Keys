"""
digital_keys.broker - the part that actually matters.

The rule, stated once:

    THE AGENT NEVER CONTROLS WHERE A SECRET GOES.

An agent can ask for "a credential for provider X" and can shape the *content*
of the request (method, relative path, query, body). It can never influence the
scheme, host, port, the injected auth header, or the TLS settings of the
destination. Those come from a Provider record that only the human can edit and
which the agent cannot see the full contents of.

The first prototype of this project got that wrong and a red-team script walked
the real key out of it in one request. Everything below exists to make that
impossible rather than merely unlikely.

Defences, in the order a request meets them:
  1. capability check   - a one-time, short-lived, scoped token
  2. policy check       - method + path prefix must be on the provider's allowlist
  3. path sanitisation  - canonicalise, then prove the result stayed in bounds
  4. host pinning       - resolve the provider host, pin the IP, refuse internal
  5. header sanitation  - strip anything auth-shaped the agent tried to add
  6. request dispatch   - inject the real secret, talk to the pinned origin
  7. response filtering - hand back the body, scrub any echo of the secret
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .crypto import derive_subkey, b64e, b64d, random_bytes, INFO_TOKEN
from .records import Provider, sanitise_for_header

# Methods an agent may ever use. GET/POST covers the overwhelming majority of
# API calls; the rest are opt-in per provider.
DEFAULT_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# Headers an agent is never allowed to set, because they carry or redirect
# credentials. Matched case-insensitively against the full header name.
FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "proxy-authenticate",
        "cookie",
        "set-cookie",
        "host",
        "x-api-key",
        "x-auth-token",
        "api-key",
        "apikey",
        "x-goog-api-key",
        "anthropic-api-key",
        "openai-api-key",
        "x-access-token",
        "authentication",
        "www-authenticate",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "forwarded",
        "x-original-url",
        "x-rewrite-url",
        "sec-fetch-site",
    }
)

# Header prefixes that must never come from the agent.
FORBIDDEN_HEADER_PREFIXES = ("x-forwarded-", "x-original-", "x-rewrite-", "proxy-")

MAX_PATH_LEN = 2048
MAX_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 120.0


class BrokerError(Exception):
    pass


class Denied(BrokerError):
    """Request refused. The message is safe to show the agent; it names no secret."""


class NoCapability(BrokerError):
    pass


# --------------------------------------------------------------------------
# Capability tokens
# --------------------------------------------------------------------------


@dataclass
class Capability:
    """
    A one-time grant: "this caller may use record R against provider P for
    method M under path prefix Q until T".

    Deliberately *not* a bearer token for the vault. It names a record, it does
    not contain one. Possessing it still requires the vault to be unsealed by
    the human, and the broker is what actually decrypts.
    """

    token_id: str
    record_id: str
    provider_id: str
    methods: tuple[str, ...]
    path_prefix: str
    issued_at: float
    expires_at: float
    spent: bool = False
    used_count: int = 0
    label: str = ""
    # One grant == one request unless the human explicitly asks otherwise.
    # This is the default because a leaked token that works forever is a much
    # worse failure than a token that expires a little too eagerly.
    single_use: bool = True


class CapabilityStore:
    """In-memory, single-use-by-default. Tokens never touch the disk."""

    def __init__(self, default_ttl: float = 300.0, max_ttl: float = 900.0):
        self._caps: dict[str, Capability] = {}
        self._lock = threading.Lock()
        self.default_ttl = default_ttl
        self.max_ttl = max_ttl

    def issue(
        self,
        record_id: str,
        provider_id: str,
        methods: list[str] | None = None,
        path_prefix: str = "/",
        ttl: float | None = None,
        label: str = "",
        single_use: bool = True,
    ) -> Capability:
        ttl = self.default_ttl if ttl is None else min(float(ttl), self.max_ttl)
        now = time.time()
        token_id = secrets.token_urlsafe(32)
        cap = Capability(
            token_id=token_id,
            record_id=record_id,
            provider_id=provider_id,
            methods=tuple(m.upper() for m in (methods or ["GET", "POST"])),
            path_prefix=path_prefix or "/",
            issued_at=now,
            expires_at=now + ttl,
            label=label,
            single_use=single_use,
        )
        with self._lock:
            self._sweep_locked()
            self._caps[token_id] = cap
        return cap

    def _sweep_locked(self) -> None:
        now = time.time()
        for k in [k for k, c in self._caps.items() if c.expires_at < now]:
            del self._caps[k]

    def redeem(self, token_id: str, method: str, path: str) -> Capability:
        """
        Consume a capability. This is the choke point: if we get here, the
        caller has a live grant and we check the request against its scope.
        """
        with self._lock:
            self._sweep_locked()
            cap = self._caps.get(token_id)
            if cap is None:
                raise NoCapability("unknown or expired capability token")
            if cap.spent:
                raise NoCapability("capability already used")
            if method.upper() not in cap.methods:
                raise Denied(f"method {method.upper()} not permitted by this grant")
            if not _path_within(path, cap.path_prefix):
                raise Denied("path not permitted by this grant")
            cap.used_count += 1
            if cap.single_use:
                cap.spent = True
            return cap

    def revoke_all(self) -> int:
        """The emergency stop. Kills every outstanding grant immediately."""
        with self._lock:
            n = len(self._caps)
            self._caps.clear()
            return n

    def outstanding(self) -> list[dict]:
        with self._lock:
            self._sweep_locked()
            return [
                {
                    "label": c.label,
                    "record_id": c.record_id,
                    "provider_id": c.provider_id,
                    "expires_in": round(max(0.0, c.expires_at - time.time()), 1),
                    "used": c.used_count,
                }
                for c in self._caps.values()
            ]


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------

_UNSAFE = re.compile(r"[\x00-\x20\x7f\\]")


# Characters allowed to stay literal inside a canonical path segment.
# Everything else is percent-encoded, which stops decoded ? # & = from
# being re-interpreted as query/fragment/parameter separators.
_PATH_SAFE = "-._~!$&'()*+,;=:@"


def sanitise_path(raw: str) -> str:
    """
    Canonicalise an agent-supplied path.

    The contract is: the result always starts with a single '/', contains no
    dot-segments, no backslashes, no control characters, and no scheme or host.
    Anything that cannot be expressed that way is rejected rather than
    "cleaned", because cleaning is how these bugs get in.
    """
    if raw is None:
        raise Denied("path is required")
    if not isinstance(raw, str):
        raise Denied("path must be a string")
    if len(raw) > MAX_PATH_LEN:
        raise Denied("path too long")
    if _UNSAFE.search(raw):
        raise Denied("path contains illegal characters")

    # Reject anything that looks like it carries its own authority. This is the
    # 'https://evil.example.com' and '//evil.example.com' and
    # 'https://openrouter.ai@evil.example.com' family.
    if raw.startswith("//") or raw.startswith("\\\\"):
        raise Denied("protocol-relative paths are not allowed")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", raw):
        raise Denied("absolute URLs are not allowed; send a path only")
    if "@" in raw.split("/", 1)[0]:
        raise Denied("userinfo in path is not allowed")

    if not raw.startswith("/"):
        raw = "/" + raw

    # Decode once, then re-encode canonically. Decoding first is what exposes
    # %2e%2e%2f style traversal to the dot-segment check below.
    try:
        decoded = urllib.parse.unquote(raw, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise Denied("path is not valid percent-encoding") from exc
    if "\\" in decoded or "\x00" in decoded:
        raise Denied("path contains illegal characters after decoding")

    # FIX: dot-segments are now REJECTED, not silently resolved. Cleaning them
    # is how scope bypasses happen: the caller sees the cleaned path, the grant
    # prefix was checked against something else, and no error is ever raised.
    segs = decoded.split("/")
    for seg in segs:
        if seg == ".." or seg in (".", "%2e", "%2E"):
            raise Denied("dot-segments are not allowed in paths; send the canonical path")

    # Re-encode exactly once with a strict, explicit allowlist, so a decoded
    # '?' or '#' cannot smuggle a query/fragment boundary back in.
    out: list[str] = []
    for seg in segs:
        if seg == "":
            continue
        try:
            out.append(urllib.parse.quote(seg, safe=_PATH_SAFE, encoding="utf-8", errors="strict"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise Denied("path is not valid UTF-8") from exc
    return "/" + "/".join(out)


def _path_within(path: str, prefix: str) -> bool:
    """
    Prefix match that respects segment boundaries.

    '/v1/keys' must NOT match prefix '/v1/key' - otherwise a grant for one
    endpoint silently covers its neighbour.
    """
    if prefix in ("", "/", "*"):
        return True
    p = path.rstrip("/") or "/"
    q = prefix.rstrip("/") or "/"
    if q == "/":
        return True
    return p == q or p.startswith(q + "/")


# --------------------------------------------------------------------------
# Destination policy
# --------------------------------------------------------------------------


@dataclass
class Destination:
    url: str
    host: str
    port: int
    scheme: str
    pinned_ip: str | None = None


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False
    # IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return _is_public_ip(str(addr.ipv4_mapped))
    # 100.64.0.0/10 carrier-grade NAT, and 169.254.169.254 metadata
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            return False
        if addr == ipaddress.ip_address("169.254.169.254"):
            return False
    return True


def resolve_destination(provider: Provider, allow_private: bool = False) -> Destination:
    """
    Turn a provider's trusted base_url into a connection target.

    For custom providers this is the SSRF chokepoint. We resolve the hostname
    ourselves and refuse anything that lands on a private, loopback, link-local
    or otherwise non-public address - which is what stops the
    'agent points the broker at 169.254.169.254 to steal cloud credentials'
    trick.
    """
    try:
        parts = urllib.parse.urlsplit(provider.base_url)
    except Exception as exc:
        raise Denied("provider base_url is unparseable") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ("https", "http"):
        raise Denied("provider base_url must be http or https")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise Denied("provider base_url must not contain userinfo")
    host = (parts.hostname or "").lower()
    if not host:
        raise Denied("provider base_url has no host")
    if scheme == "https" and not allow_private:
        pass  # TLS is required for non-local providers, enforced below
    if scheme == "http" and not allow_private:
        raise Denied(
            "plain http is not allowed for a remote provider; "
            "use https (or explicitly mark a localhost provider)"
        )

    port = parts.port or (443 if scheme == "https" else 80)

    pinned = None
    if not allow_private:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise Denied(f"cannot resolve provider host {host!r}") from exc
        for info in infos:
            ip = info[4][0]
            if not _is_public_ip(ip):
                raise Denied(
                    f"provider host {host!r} resolves to non-public address {ip}; "
                    "refusing to send a credential there"
                )
            pinned = ip
            break

    return Destination(
        url=provider.base_url, host=host, port=port, scheme=scheme, pinned_ip=pinned
    )


def provider_origin(provider: Provider) -> str:
    """
    scheme://host[:port] - and nothing else.

    This is the single source of authority for where a secret may go. A base
    path in base_url is documentation and a default allowlist hint, never
    something the request is built from.
    """
    dest = resolve_destination(provider, allow_private=True)
    default_port = 443 if dest.scheme == "https" else 80
    if dest.port and dest.port != default_port:
        return f"{dest.scheme}://{dest.host}:{dest.port}"
    return f"{dest.scheme}://{dest.host}"


def base_path_of(provider: Provider) -> str:
    """The path component of base_url, e.g. '/api/v1' for OpenRouter."""
    import urllib.parse

    parts = urllib.parse.urlsplit(provider.base_url)
    return (parts.path or "").rstrip("/")


def build_request_url(provider: Provider, path: str) -> str:
    """
    Assemble the final URL: pinned origin + the agent's sanitised path.

    The agent's path is the *real* path on the host - '/api/v1/chat/completions'
    for OpenRouter, not a second '/api/v1'. The base path in base_url is not
    prepended here, because doing that double-prefixes any path the agent
    already spelled out in full, and 'be clever about double prefixes' is how
    path bugs turn into traversal bugs.
    """
    if not path.startswith("/"):
        path = "/" + path
    return provider_origin(provider) + path


def sanitise_headers(agent_headers: dict[str, str] | None, provider: Provider) -> dict[str, str]:
    """
    Agent headers are kept only if they are boring.

    Anything that could carry a credential, redirect the request, or spoof the
    destination is dropped silently. The provider's own headers are then
    applied on top so the real auth wins even if a header slipped through.
    """
    out: dict[str, str] = {}
    for name, value in (agent_headers or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        low = name.lower().strip()
        if not low or low in FORBIDDEN_HEADERS:
            continue
        if any(low.startswith(p) for p in FORBIDDEN_HEADER_PREFIXES):
            continue
        # Header name must be a token, not a smuggling vector.
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
            continue
        try:
            out[name] = sanitise_for_header(value)
        except TypeError:
            continue
    for name, value in (provider.extra_headers or {}).items():
        out[name] = sanitise_for_header(value)
    return out


def apply_secret(
    headers: dict[str, str], query: str, provider: Provider, secret: str
) -> tuple[dict[str, str], str]:
    """
    Inject the real credential at the last possible moment.

    This is the only function in the project that ever sees a plaintext secret
    for the purpose of making a network request, and it returns the request
    materials - never the secret - to its caller.
    """
    secret = sanitise_for_header(secret)
    if not secret:
        raise Denied("stored credential is empty")
    style = provider.auth_style
    if style == "none":
        return headers, query
    if style == "bearer":
        headers[provider.auth_header] = f"{provider.auth_prefix}{secret}"
    elif style == "header":
        headers[provider.auth_header] = secret
    elif style == "query":
        if not provider.auth_query_param:
            raise Denied("provider is misconfigured: no auth_query_param")
        parts = urllib.parse.urlsplit(f"?{query}" if query else "")
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        q = [(k, v) for k, v in q if k != provider.auth_query_param]
        q.append((provider.auth_query_param, secret))
        query = urllib.parse.urlencode(q, quote_via=urllib.parse.quote)
    else:
        raise Denied(f"unknown auth_style {style!r}; refusing to guess")
    return headers, query


# --------------------------------------------------------------------------
# The dispatcher
# --------------------------------------------------------------------------


class SecretLease:
    """
    A single, un-renewable permission to use one secret once.

    The vault key stays unsealed for exactly as long as the outbound request is
    in flight, and not one instruction longer. `__exit__` seals the vault no
    matter how the request ended, so a timeout, a 500, or a Ctrl-C all leave the
    vault closed.
    """

    def __init__(self, vault, passphrase: str):
        self._vault = vault
        self._passphrase = passphrase
        self._cm = None
        self._handle = None
        self.secret: str | None = None
        self.record_id: str = ""
        self.provider_id: str = ""

    def __enter__(self) -> "SecretLease":
        self._cm = self._vault.unlock(self._passphrase)
        self._handle = self._cm.__enter__()
        return self

    def load(self, record_id: str) -> Record:  # type: ignore[name-defined]
        rec = self._handle.get(record_id)
        self.record_id = rec.id
        self.secret = rec.secret
        return rec

    def provider(self, provider_id: str) -> Provider:
        return self._handle.provider(provider_id)

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            if self._cm is not None:
                self._cm.__exit__(exc_type, exc, tb)
        finally:
            self.secret = None
            self._handle = None
            self._cm = None
        return False


@dataclass
class BrokerConfig:
    """
    Everything the broker needs that is not secret.

    `unlock_fn` is how the human authorises a request. On a desktop this is a
    PIN prompt; in tests it is a lambda. The broker itself never holds a
    long-lived passphrase and never has an "unlocked" state of its own.
    """

    vault_path: str
    max_response_bytes: int = 32 * 1024 * 1024
    timeout: float = DEFAULT_TIMEOUT
    allow_private_for_custom: bool = False
    audit_sink: Any = None
    unlock_fn: Any = None


class AuditLog:
    """
    Append-only record of what the broker did, in a form that is safe to show.

    Crucially: it records the *handle* (a truncated hash of the record id) and
    never the secret, never a full record id, and never a URL that the agent
    could use to fingerprint. If you find a secret in this log, that's a bug.
    """

    def __init__(self, path: str | None = None, retain: int = 5000):
        self.path = path
        self.retain = retain
        self._entries: list[dict] = []
        self._lock = threading.Lock()

    def record(self, **fields: Any) -> dict:
        entry = {"ts": round(time.time(), 3), **fields}
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self.retain:
                del self._entries[: len(self._entries) - self.retain]
        return entry

    def entries(self, limit: int = 200) -> list[dict]:
        with self._lock:
            return list(self._entries)[-limit:]

    def redacted(self, limit: int = 200) -> list[dict]:
        """
        Return the log with every field that could contain a secret redacted.
        Used by the 'show audit' command so that printing it is never itself a
        leak.
        """
        safe_keys = {
            "ts",
            "event",
            "ok",
            "provider_id",
            "method",
            "path",
            "status",
            "handle",
            "duration_ms",
            "reason",
            "revoked",
        }
        out = []
        for e in self.entries(limit):
            out.append({k: v for k, v in e.items() if k in safe_keys})
        return out


def _audit_handle(record_id: str) -> str:
    """A short, non-reversible tag for a record, safe to log."""
    from hashlib import sha256

    return sha256(("kh:" + record_id).encode()).hexdigest()[:12]


class Dispatcher:
    """
    The thing opencode / goose / curl actually talk to.

    `handle_request` is the single entry point and the single place a secret is
    decrypted. It returns (status, body_bytes, headers) and nothing else - the
    plaintext secret is not in scope anywhere the caller can reach it.
    """

    def __init__(self, config: BrokerConfig):
        from .vault import Vault

        self.config = config
        self.vault = Vault(config.vault_path)
        self.caps = CapabilityStore()
        self.audit = AuditLog()

    # -- capability issuance (human side) ---------------------------------

    def grant(
        self,
        record_id: str,
        provider_id: str,
        methods: list[str] | None = None,
        path_prefix: str = "/",
        ttl: float | None = None,
        label: str = "",
        single_use: bool = True,
    ) -> Capability:
        cap = self.caps.issue(record_id, provider_id, methods, path_prefix, ttl, label, single_use)
        self.audit.record(event="grant", provider_id=provider_id, handle=_audit_handle(record_id), label=label)
        return cap

    def emergency_stop(self) -> int:
        n = self.caps.revoke_all()
        self.audit.record(event="emergency_stop", revoked=n)
        return n

    # -- the request path -------------------------------------------------

    def handle_request(self, req: dict) -> tuple[int, dict, dict]:
        """
        `req` is the agent's JSON request:
            { token, method, path, query, headers, body }

        Returns (status, response_headers, parsed_json_or_text).
        """
        started = time.time()
        token = req.get("token") or ""
        method = str(req.get("method", "GET")).upper()
        raw_path = req.get("path", "/")
        query = req.get("query", "") or ""
        agent_headers = req.get("headers") or {}
        body = req.get("body")

        # FIX: canonicalise BEFORE the grant scope check. Checking the raw path
        # first let '/v1/keys/../../admin' satisfy a '/v1/keys' grant and then
        # canonicalise to '/admin' -- the scope check was bypassable.
        try:
            path = sanitise_path(raw_path)
        except Denied as exc:
            self.audit.record(event="denied", reason=str(exc), method=method, path=str(raw_path)[:200])
            return 400, {"error": str(exc)}, {}

        try:
            cap = self.caps.redeem(token, method, path)
        except (NoCapability, Denied) as exc:
            self.audit.record(event="denied", reason=str(exc), method=method, path=path[:200])
            return 403, {"error": str(exc)}, {}

        record_id, provider_id = cap.record_id, cap.provider_id
        handle_tag = _audit_handle(record_id)

        # Everything below happens inside the lease, so the vault is only
        # unsealed while we are actively building and sending the request.
        try:
            with SecretLease(self.vault, self._authorise()) as lease:
                record = lease.load(record_id)
                provider = lease.provider(provider_id)

                if not record.agent_capable:
                    raise Denied("this record is not usable by agents")
                if method not in DEFAULT_METHODS:
                    raise Denied(f"method {method} is not permitted")

                destination = resolve_destination(provider, self.config.allow_private_for_custom)
                if not _path_within(path, "/"):
                    raise Denied("bad path")

                # Provider-level allowlist narrows the capability's own scope.
                # Both checks run against the real host path.
                if provider.allowed_path_prefixes:
                    prefixes = provider.allowed_path_prefixes
                else:
                    bp = base_path_of(provider)
                    prefixes = [bp] if bp else []
                if prefixes and not any(_path_within(path, p) for p in prefixes):
                    raise Denied(
                        f"path not allowed for this provider (allowed: {', '.join(prefixes)})"
                    )
                if method not in [m.upper() for m in provider.allowed_methods]:
                    raise Denied("method not allowed for this provider")

                headers = sanitise_headers(agent_headers, provider)
                if len(json.dumps(headers)) > 8192:
                    raise Denied("headers too large")
                if query and len(query) > 4096:
                    raise Denied("query too long")
                if body is not None:
                    if not isinstance(body, (str, dict, list)):
                        raise Denied("body must be a string or JSON value")
                    if isinstance(body, str) and len(body.encode("utf-8")) > MAX_BODY_BYTES:
                        raise Denied("body too large")
                    if not isinstance(body, str):
                        body = json.dumps(body)

                final_url = build_request_url(provider, path)
                if not final_url.startswith("https://") and not self.config.allow_private_for_custom:
                    raise Denied("refusing to send a credential over plain http")

                headers, final_query = apply_secret(headers, query, provider, record.secret)

                # FIX: actually pass the validated IP down, so the connection
                # uses the address we checked instead of re-resolving.
                status, resp_headers, payload = self._send(
                    final_url, final_query, method, headers, body,
                    pinned_ip=destination.pinned_ip,
                )

                # FIX: scrub INSIDE the lease. This used to run after the
                # context closed, so the plaintext secret stayed reachable in
                # the `record` object well past the nominal lease boundary.
                payload = self._scrub_response(payload, record.secret)
        except Denied as exc:
            self.audit.record(
                event="denied", reason=str(exc), provider_id=provider_id,
                handle=handle_tag, method=method, path=path[:200],
            )
            return 403, {"error": str(exc)}, {}
        except Exception as exc:  # noqa: BLE001 - never leak the exception text
            self.audit.record(event="error", reason=type(exc).__name__, provider_id=provider_id, handle=handle_tag)
            return 502, {"error": "upstream request failed"}, {}

        # Drop every reference we hold to plaintext as soon as we legally can.
        secret = None
        record = None
        self.audit.record(
            event="forwarded", ok=True, provider_id=provider_id, handle=handle_tag,
            method=method, path=path[:200], status=status,
            duration_ms=round((time.time() - started) * 1000, 1),
        )
        return status, resp_headers, payload

    def _authorise(self) -> str:
        if self.config.unlock_fn is None:
            raise Denied("this broker has no human authorisation channel configured")
        return self.config.unlock_fn()

    def _send(self, url, query, method, headers, body, pinned_ip: str | None = None):
        """
        Dispatch to an already-validated destination.

        FIX (DNS rebinding): we connect to the IP that was actually validated
        instead of handing the hostname to http.client, which does its own
        second DNS lookup. The old code computed the checked IP, stored it on
        the Destination, documented it as a pin -- and then never used it. A
        hostname could resolve to a public address during validation and to
        127.0.0.1 at connect time, which defeats the whole SSRF check.

        The pinned IP is used for the TCP connection only. TLS still verifies
        the certificate against the real hostname, so SNI and cert validation
        behave exactly as they would without pinning.
        """
        import http.client
        import socket
        import urllib.parse

        parts = urllib.parse.urlsplit(url)
        target = parts.path or "/"
        if query:
            target += "?" + query

        connect_host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)

        if pinned_ip:
            headers = dict(headers or {})
            headers.setdefault("Host", parts.netloc)
            connect_host = pinned_ip

        conn = None
        try:
            if parts.scheme == "https":
                import ssl

                conn = _PinnedHTTPSConnection(
                    parts.hostname, port, connect_host,
                    timeout=self.config.timeout, context=ssl.create_default_context(),
                )
            else:
                if pinned_ip:
                    conn = _PinnedHTTPConnection(parts.hostname, port, connect_host,
                                                 timeout=self.config.timeout)
                else:
                    conn = http.client.HTTPConnection(connect_host, port, timeout=self.config.timeout)

            if not headers.get("Accept-Encoding"):
                # We do not decompress here; a compressed body would defeat
                # the response scrubber, so ask for identity to keep it readable.
                headers["Accept-Encoding"] = "identity"

            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(self.config.max_response_bytes)
            ctype = resp.getheader("Content-Type", "")
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                parsed = raw.decode("utf-8", errors="replace")
            return resp.status, {"Content-Type": ctype}, parsed
        finally:
            if conn is not None:
                conn.close()

    def _scrub_response(self, payload, secret: str) -> Any:
        """
        Providers occasionally echo the key back (error bodies, debug output).
        If one does, the agent must not get to see it. Replace any occurrence of
        the secret in the response with a placeholder.
        """
        if not secret:
            return payload
        marker = "***"
        if isinstance(payload, str):
            return payload.replace(secret, marker)
        if isinstance(payload, dict):
            redacted = {}
            for k, v in payload.items():
                if k.lower() in ("authorization", "api_key", "apikey", "key", "token", "access_token"):
                    redacted[k] = marker
                elif isinstance(v, str):
                    redacted[k] = v.replace(secret, marker)
                elif isinstance(v, (dict, list)):
                    redacted[k] = self._scrub_response(v, secret)
                else:
                    redacted[k] = v
            return redacted
        if isinstance(payload, list):
            return [self._scrub_response(x, secret) for x in payload]
        return payload


# --------------------------------------------------------------------------
# Pinned connections (DNS-rebinding fix)
# --------------------------------------------------------------------------
#
# These subclasses exist for one reason: http.client re-resolves the hostname
# itself, so passing a hostname would bypass the IP we validated. Each one
# connects the socket to `connect_host` (the validated IP) while presenting
# `hostname` to TLS, so certificate and SNI checks stay correct.


def _make_pinned_connections():
    import http.client
    import socket

    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def __init__(self, hostname, port, connect_host, **kwargs):
            super().__init__(hostname, port, **kwargs)
            self._connect_host = connect_host

        def connect(self):
            self.sock = socket.create_connection(
                (self._connect_host, self.port), self.timeout, self.source_address
            )
            if self._tunnel_host:
                self._tunnel()

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, hostname, port, connect_host, **kwargs):
            super().__init__(hostname, port, **kwargs)
            self._connect_host = connect_host

        def connect(self):
            sock = socket.create_connection(
                (self._connect_host, self.port), self.timeout, self.source_address
            )
            if self._tunnel_host:
                self.sock = sock
                self._tunnel()
                return
            self.sock = self._context.wrap_socket(
                sock, server_hostname=self.host
            )

    return _PinnedHTTPConnection, _PinnedHTTPSConnection


_PinnedHTTPConnection, _PinnedHTTPSConnection = _make_pinned_connections()
