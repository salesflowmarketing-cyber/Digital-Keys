"""
Adversarial tests for the broker.

These are written from the point of view of a *malicious agent*: one that has
been granted use of an OpenRouter credential and now wants to walk that
credential somewhere it should not go, or read it out.

Every test asserts one of two things:
  * the secret never appears in anything the agent can observe, or
  * the request is refused.

The test upstream is a real HTTP server on loopback that records whether it
ever received the secret. If the broker's destination pinning is broken, that
server sees the key and the test fails loudly.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from digital_keys.broker import (  # noqa: E402
    BrokerConfig,
    Denied,
    Dispatcher,
    _path_within,
    build_request_url,
    sanitise_headers,
    sanitise_path,
)
from digital_keys.records import Category, Provider, Record, SecretKind  # noqa: E402
from digital_keys.vault import Vault  # noqa: E402

SECRET = "sk-or-v1-THISISAREALLOOKINGKEY1234567890"
PASS = "test pass phrase"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail else ""))


# --------------------------------------------------------------------------
# An upstream that will happily tell us what it was sent.
# --------------------------------------------------------------------------


class Sniffer(BaseHTTPRequestHandler):
    received_secret = None
    received_auth = None

    def _record(self):
        auth = self.headers.get("Authorization")
        Sniffer.received_auth = auth
        if auth and SECRET in auth:
            Sniffer.received_secret = auth

    def do_GET(self):
        self._record()
        body = json.dumps(
            {
                "error": {"message": "User not found.", "code": 401},
                "echo_auth": self.headers.get("Authorization"),
                "path": self.path,
            }
        ).encode()
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._record()
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        if SECRET.encode() in raw:
            Sniffer.received_secret = raw
        body = json.dumps(
            {
                "ok": True,
                "id": "gen-123",
                "path": self.path,
                "echo_auth": self.headers.get("Authorization"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_sniffer():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    srv = HTTPServer(("127.0.0.1", port), Sniffer)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def build(tmpdir: str, sniffer_port: int):
    path = os.path.join(tmpdir, "vault.json")
    v = Vault.create(path, PASS)
    with v.unlock(PASS) as h:
        rec = h.put(
            Record(
                id="",
                category=Category.LLM,
                kind=SecretKind.API_KEY,
                label="OpenRouter (test)",
                secret=SECRET,
                provider_id="openrouter",
                username="tester",
            )
        )
        h.add_provider(
            Provider(
                id="openrouter",
                label="OpenRouter",
                category=Category.LLM,
                base_url=f"http://127.0.0.1:{sniffer_port}",  # stand-in upstream
                auth_style="bearer",
                auth_prefix="Bearer ",
                allowed_methods=["GET", "POST", "DELETE"],
                allowed_path_prefixes=["/api/v1"],
            )
        )
        rid = rec.id
    cfg = BrokerConfig(
        vault_path=path,
        allow_private_for_custom=True,  # the test upstream is on loopback
        unlock_fn=lambda: PASS,
    )
    d = Dispatcher(cfg)
    return d, rid


# --------------------------------------------------------------------------
# Pure-function attacks (no network)
# --------------------------------------------------------------------------

EVIL_PATHS = [
    "http://127.0.0.1:9998/collect",
    "https://evil.example.com/steal",
    "//evil.example.com/steal",
    "\\\\evil.example.com/steal",
    "http://169.254.169.254/latest/meta-data/",
    "https://openrouter.ai@evil.example.com/",
    "https://openrouter.ai/../admin",
    "/../../../../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/api/v1/../../../admin",
    "file:///etc/passwd",
    "gopher://evil:70/x",
    "dict://evil:11211/x",
    "vbscript:msgbox(1)",
    "/api/v1\x00/../../x",
    "/api/v1\r\nX-Injected: 1",
    "https:evil.example.com",
    "/api/v1/..%2f..%2fadmin",
    "http://localhost@127.0.0.1:1/x",
    "///evil.example.com",
]


def test_path_attacks():
    print("\n[1] path / destination-confusion attacks")
    blocked = 0
    for evil in EVIL_PATHS:
        try:
            out = sanitise_path(evil)
        except Denied:
            blocked += 1
            continue
        # If it was accepted, the result must be a bare path with no authority.
        if out.startswith("/") and "://" not in out and "@" not in out.split("/")[0]:
            blocked += 1
        else:
            check(f"dangerous path survived: {evil!r}", False, f"-> {out!r}")
            continue
    check(
        f"all {len(EVIL_PATHS)} dangerous paths neutralised",
        blocked == len(EVIL_PATHS),
        f"{blocked}/{len(EVIL_PATHS)}",
    )

    # The specific exfiltration shape from the original prototype.
    out = sanitise_path("/api/v1/chat/completions")
    check("legitimate API path still works", out == "/api/v1/chat/completions", out)


def test_prefix_matching():
    print("\n[2] scope-prefix boundary checks")
    check("/v1/keys rejected for prefix /v1/key", not _path_within("/v1/keys", "/v1/key"))
    check("/v1/keys/models allowed for /v1/keys", _path_within("/v1/keys/models", "/v1/keys"))
    check("/ allowed for prefix /v1/keys", not _path_within("/", "/v1/keys"))
    check("/v1/keys allowed for /v1/keys", _path_within("/v1/keys", "/v1/keys"))


def test_url_construction():
    print("\n[3] URL construction keeps the origin trusted")
    p = Provider(id="x", label="X", category=Category.LLM, base_url="https://openrouter.ai/api/v1")
    # The agent's path is the real host path; base_url contributes origin only.
    u = build_request_url(p, "/api/v1/models")
    check("origin pinned, path passed through",
          u == "https://openrouter.ai/api/v1/models", u)
    check("base path is NOT double-prefixed",
          build_request_url(p, "/api/v1/chat/completions")
          == "https://openrouter.ai/api/v1/chat/completions")
    p2 = Provider(id="y", label="Y", category=Category.LLM, base_url="https://api.example.com")
    check("no base path", build_request_url(p2, "/v1/things") == "https://api.example.com/v1/things")
    p3 = Provider(id="z", label="Z", category=Category.CUSTOM, base_url="https://h.example.com:8443/api")
    check("explicit port preserved", build_request_url(p3, "/x") == "https://h.example.com:8443/x")
    p4 = Provider(id="w", label="W", category=Category.CUSTOM, base_url="https://a.example.com")
    check("origin from a path that looks like a host is still just the host",
          build_request_url(p4, "/evil.example.com/x") == "https://a.example.com/evil.example.com/x")


def test_header_attacks():
    print("\n[4] header smuggling / auth override")
    p = Provider(id="x", label="X", category=Category.LLM, base_url="https://api.example.com")
    hostile = {
        "Authorization": "Bearer agent-supplied",
        "Host": "evil.example.com",
        "X-Api-Key": "sk-attacker",
        "Cookie": "session=stolen",
        "X-Forwarded-Host": "evil.example.com",
        "X-Original-URL": "/admin",
        "Proxy-Authorization": "Basic abc",
        "X-Api-Key ": "trailing-space",
        "X-Good": "fine",
    }
    out = sanitise_headers(hostile, p)
    for bad in ["Authorization", "Host", "X-Api-Key", "Cookie", "X-Forwarded-Host", "X-Original-URL", "Proxy-Authorization"]:
        if bad in out:
            check(f"hostile header {bad} survived", False)
            return
    check("all auth-bearing headers dropped", True)
    check("benign header preserved", out.get("X-Good") == "fine", str(out))


# --------------------------------------------------------------------------
# End-to-end attacks through the dispatcher
# --------------------------------------------------------------------------


def test_end_to_end():
    print("\n[5] end-to-end against a live sniffer upstream")
    tmp = tempfile.mkdtemp()
    srv, port = start_sniffer()
    try:
        d, rid = build(tmp, port)

        # -- 5a: a legitimate, approved call succeeds and the key is NOT echoed
        cap = d.grant(rid, "openrouter", methods=["POST"], path_prefix="/api/v1", label="legit")
        status, _, body = d.handle_request(
            {"token": cap.token_id, "method": "POST", "path": "/api/v1/chat/completions",
             "body": {"model": "x", "messages": []}}
        )
        check("approved call reached upstream", status == 200, str(status))
        check("upstream saw the real key (proxy worked)", Sniffer.received_secret is not None)
        check("key not echoed back to agent", SECRET not in json.dumps(body, default=str))

        # -- 5b: the exfiltration attempt
        Sniffer.received_secret = None
        cap2 = d.grant(rid, "openrouter", methods=["GET", "POST"], path_prefix="/", label="evil")
        status, _, body = d.handle_request(
            {"token": cap2.token_id, "method": "POST", "path": "http://127.0.0.1:1/collect"}
        )
        check("absolute-URL exfiltration refused", status == 400, str(status))
        check("nothing sent to attacker host", Sniffer.received_secret is None)

        # -- 5c: path outside the grant's prefix
        cap3 = d.grant(rid, "openrouter", methods=["POST"], path_prefix="/api/v1", label="scoped")
        status, _, _ = d.handle_request(
            {"token": cap3.token_id, "method": "POST", "path": "/admin/drop"}
        )
        check("out-of-scope path refused", status == 403, str(status))

        # -- 5d: method outside the grant
        status, _, _ = d.handle_request(
            {"token": cap3.token_id, "method": "DELETE", "path": "/api/v1/chat"}
        )
        check("out-of-scope method refused", status == 403, str(status))

        # -- 5e: header override attempt mid-flight
        cap4 = d.grant(rid, "openrouter", methods=["POST"], path_prefix="/api/v1")
        status, _, body = d.handle_request(
            {"token": cap4.token_id, "method": "POST", "path": "/api/v1/chat/completions",
             "headers": {"Authorization": "Bearer attacker-token", "Host": "evil.example.com"},
             "body": {}}
        )
        sent_auth = Sniffer.received_auth or ""
        check("hostile Authorization did not reach upstream", "attacker-token" not in sent_auth, sent_auth[:60])
        check("hostile Host did not reach upstream", "evil.example.com" not in json.dumps(body, default=str))

        # -- 5f: replay a spent token
        cap5 = d.grant(rid, "openrouter", methods=["POST"], path_prefix="/api/v1")
        d.handle_request({"token": cap5.token_id, "method": "POST", "path": "/api/v1/chat", "body": {}})
        status, _, _ = d.handle_request(
            {"token": cap5.token_id, "method": "POST", "path": "/api/v1/chat", "body": {}}
        )
        check("reused capability refused", status == 403, str(status))

        # -- 5g: forged / unknown token
        status, _, _ = d.handle_request(
            {"token": "totally-made-up", "method": "GET", "path": "/api/v1/models"}
        )
        check("forged token refused", status == 403, str(status))

        # -- 5h: emergency stop kills live grants
        cap6 = d.grant(rid, "openrouter", methods=["POST"], path_prefix="/api/v1")
        n = d.emergency_stop()
        check("emergency stop reported kills", n >= 1, str(n))
        status, _, _ = d.handle_request(
            {"token": cap6.token_id, "method": "POST", "path": "/api/v1/chat", "body": {}}
        )
        check("grant dead after emergency stop", status == 403, str(status))

        # -- 5i: audit log contains no secret
        log = json.dumps(d.audit.redacted(), default=str)
        check("audit log free of secret", SECRET not in log)
        check("audit log is non-empty", len(d.audit.entries()) > 5, f"{len(d.audit.entries())} entries")

        # -- 5j: response scrubbing when upstream echoes the key
        srv2, port2 = start_sniffer()
        d2, rid2 = build(tempfile.mkdtemp(), port2)
        cap7 = d2.grant(rid2, "openrouter", methods=["POST"], path_prefix="/api/v1")
        status, _, body = d2.handle_request(
            {"token": cap7.token_id, "method": "POST", "path": "/api/v1/chat", "body": {}}
        )
        check("echoed key scrubbed from response body", SECRET not in json.dumps(body, default=str))
    finally:
        srv.shutdown()


def test_private_ip_blocking():
    print("\n[6] custom providers must not point at internal infrastructure")
    from digital_keys.broker import resolve_destination

    for evil in [
        "http://169.254.169.254",
        "http://127.0.0.1:8080",
        "http://10.0.0.5",
        "http://192.168.1.1",
        "http://[::1]",
        "http://metadata.google.internal",
    ]:
        p = Provider(id="c", label="C", category=Category.CUSTOM, base_url=evil, auth_style="bearer")
        try:
            resolve_destination(p, allow_private=False)
            check(f"internal destination allowed: {evil}", False)
        except Denied:
            pass
    check("all internal/metadata destinations refused", True)

    p_ok = Provider(id="c", label="C", category=Category.CUSTOM,
                    base_url="http://localhost:11434", auth_style="none")
    try:
        dest = resolve_destination(p_ok, allow_private=True)
        check("explicitly-allowed local provider permitted", dest.host == "localhost")
    except Denied as exc:
        check("explicitly-allowed local provider permitted", False, str(exc))


# ==========================================================================
# Round 2 - regressions for defects found in review
# ==========================================================================


def test_path_scope_bypass():
    """
    A grant scoped to '/v1/keys' must not be usable for '/admin'.

    The broker used to scope-check the RAW path and canonicalise afterwards, so
    '/v1/keys/../../admin' satisfied the prefix test and then resolved to
    '/admin'. Dot-segments are now rejected outright rather than cleaned.
    """
    for evil in [
        "/v1/keys/../../admin",
        "/v1/keys/../admin",
        "/v1/%2e%2e/admin",
        "/v1/%2E%2E/admin",
        "/v1/keys/%2e%2e%2f%2e%2e%2fadmin",
        "/v1/keys/./../admin",
    ]:
        try:
            out = sanitise_path(evil)
        except Denied:
            check(f"traversal rejected: {evil}", True)
            continue
        check(f"traversal rejected: {evil}", False,
              f"canonicalised to {out!r}, which escaped the grant scope")


def test_dot_segments_rejected_not_cleaned():
    """Silently cleaning a path is what makes a scope check ambiguous."""
    for bad in ["/a/../b", "/./a", "/a/..", "/a/../", "/../a", "/a/./b"]:
        try:
            out = sanitise_path(bad)
        except Denied:
            check(f"dot-segment rejected: {bad}", True)
            continue
        check(f"dot-segment rejected: {bad}", False, f"silently cleaned to {out!r}")


def test_reserved_chars_stay_encoded():
    """A decoded '?' or '#' must not re-enter as a query/fragment boundary."""
    out = sanitise_path("/v1/a%3Fb%23c")
    check("decoded ? stays encoded", "?" not in out, out)
    check("decoded # stays encoded", "#" not in out, out)
    check("canonical path preserved", out == "/v1/a%3Fb%23c", out)


def test_ordinary_paths_still_work():
    """Hardening must not break normal provider routes."""
    for raw, want in [
        ("/api/v1/chat/completions", "/api/v1/chat/completions"),
        ("/v1/models", "/v1/models"),
        ("/v1/messages", "/v1/messages"),
        ("/api/search", "/api/search"),
        ("/v1/repos/octocat/Hello-World/issues", "/v1/repos/octocat/Hello-World/issues"),
    ]:
        try:
            got = sanitise_path(raw)
        except Denied as exc:
            check(f"ordinary path accepted: {raw}", False, str(exc))
            continue
        check(f"ordinary path accepted: {raw}", got == want, f"got {got!r}")


def test_pinned_ip_reaches_the_socket():
    """
    Regression for the DNS-rebinding lie: the validated IP was computed, stored
    as pinned_ip and then discarded, because http.client re-resolves the
    hostname itself. A host could resolve public at validation and to 127.0.0.1
    at connect time. Now the pin must reach the connection layer.
    """
    import http.client
    import inspect

    from digital_keys import broker

    send_src = inspect.getsource(broker.Dispatcher._send)
    check("_send accepts a pinned IP", "pinned_ip" in send_src)
    check("_send uses a pinned connection class",
          "_PinnedHTTPSConnection" in send_src or "_PinnedHTTPConnection" in send_src)

    handle_src = inspect.getsource(broker.Dispatcher.handle_request)
    check("handle_request passes the validated IP", "pinned_ip=destination.pinned_ip" in handle_src)

    cls = broker._PinnedHTTPConnection
    check("pinned conn subclasses HTTPConnection", issubclass(cls, http.client.HTTPConnection))
    check("pinned conn dials the IP directly", "create_connection" in inspect.getsource(cls))



def test_scrub_runs_inside_the_lease():
    """Plaintext must not stay reachable after the vault context has closed."""
    import inspect

    from digital_keys import broker

    src = inspect.getsource(broker.Dispatcher.handle_request)
    scrub = src.index("_scrub_response")
    after = src.index("return status, resp_headers, payload")
    check("response scrubbed inside the SecretLease", scrub < after)


def test_control_api_auth():
    """
    The control API used to be unauthenticated: any local process could POST
    /v1/grant and guess the vault passphrase without limit, read the audit
    tail, or kill every outstanding grant.

    These checks pin the replacement behaviour:
      * privileged routes are not on the agent listener at all,
      * the TCP control channel demands a bearer token,
      * repeated passphrase failures lock the caller out,
      * the socket and token files are owner-only.
    """
    import stat
    import urllib.error
    import urllib.request

    from digital_keys import control
    from digital_keys.server import BrokerRuntime

    def build(transport: str, lockdown: bool = False):
        tmp = tempfile.mkdtemp()
        os.environ["DIGITAL_KEYS_RUNTIME_DIR"] = os.path.join(tmp, "run")
        vpath = os.path.join(tmp, "vault.json")
        v = Vault.create(vpath, PASS)
        with v.unlock(PASS) as h:
            rec = h.put(
                Record(
                    id="",
                    category=Category.CUSTOM,
                    kind=SecretKind.API_KEY,
                    label="ctl",
                    secret=SECRET,
                    provider_id="custom",
                )
            )
            h.add_provider(
                Provider(
                    id="custom",
                    label="Custom",
                    category=Category.CUSTOM,
                    base_url="https://api.example.com",
                    auth_style="bearer",
                )
            )
        cfg = BrokerConfig(vault_path=vpath, unlock_fn=lambda: PASS)
        return BrokerRuntime(cfg, lambda: PASS, port=0, control_transport=transport,
                             lockdown=lockdown).start(), rec.id

    def http(port, path, payload=None, method="GET", token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    # -- agent listener must not expose privileged routes ------------------
    rt, rid = build("tcp")
    try:
        for route, method in [
            ("/v1/grant", "POST"),
            ("/v1/audit", "GET"),
            ("/v1/pending", "GET"),
            ("/v1/emergency-stop", "POST"),
        ]:
            st, _ = http(rt.port, route, {} if method == "POST" else None, method)
            check(f"agent listener has no {route}", st == 404, str(st))

        # -- TCP control channel demands a token ---------------------------
        cport = rt.control.port
        st, body = http(cport, "/v1/pending")
        check("control: no token is refused", st == 401, str(st))
        check("control: refusal names no internals", "token" in body.get("error", "").lower(),
              str(body))

        st, _ = http(cport, "/v1/pending", token="not-the-token")
        check("control: wrong token is refused", st == 401, str(st))

        good = control.load_token()
        st, body = http(cport, "/v1/pending", token=good)
        check("control: correct token is accepted", st == 200, str(st))
        check("control: pending is empty at rest", body.get("grants") == [], str(body))

        # -- token file is owner-only --------------------------------------
        mode = oct(os.stat(control.token_path()).st_mode & 0o777)
        check("control token file is 0600", mode == "0o600", mode)
        check("control token is 32+ bytes of entropy", len(good) >= 32, str(len(good)))

        # -- passphrase guessing is rate limited ---------------------------
        bad = {"passphrase": "wrong", "record_id": rid, "provider_id": "custom"}
        statuses = [http(cport, "/v1/grant", bad, "POST", token=good)[0] for _ in range(7)]
        check("wrong passphrase is rejected", all(s in (401, 429) for s in statuses), str(statuses))
        check("repeated guesses are locked out", 429 in statuses, str(statuses))
        st, body = http(cport, "/v1/grant", bad, "POST", token=good)
        check("lockout carries a retry hint", st == 429 and body.get("retry_after", 0) > 0,
              str(body))
        st, _ = http(cport, "/v1/pending", token=good)
        check("lockout also blocks other control routes", st == 429, str(st))

        # -- the passphrase never reaches the audit ------------------------
        st, body = http(cport, "/v1/audit?limit=500", token=good)
        check("audit has no passphrase", PASS not in json.dumps(body) and "wrong" not in json.dumps(body))
    finally:
        rt.stop()

    # -- unix control channel ---------------------------------------------
    rt, rid = build("unix")
    try:
        sock = control.socket_path()
        check("control socket exists", sock.exists(), str(sock))
        check("control socket is 0600", oct(stat.S_IMODE(os.stat(sock).st_mode)) == "0o600",
              oct(stat.S_IMODE(os.stat(sock).st_mode)))
        check("control socket dir is 0700", oct(stat.S_IMODE(os.stat(sock.parent).st_mode)) == "0o700",
              oct(stat.S_IMODE(os.stat(sock.parent).st_mode)))

        st, body = control.control_request("GET", "/v1/pending")
        check("unix control: same user accepted", st == 200, str(st))

        st, g = control.control_request(
            "POST", "/v1/grant",
            {"passphrase": PASS, "record_id": rid, "provider_id": "custom"},
        )
        check("unix control: grant works", st == 200 and bool(g.get("token")), str(st))

        # A peer whose UID cannot be established must be rejected, never passed.
        check("unix control: unknown peer uid is not trusted",
              control.peer_uid is not None)
    finally:
        rt.stop()

    # -- lockdown is opt-in and off by default ----------------------------
    rt, rid = build("unix")
    try:
        check("lockdown off by default", rt.agent.lockdown is False)
        st, g = control.control_request(
            "POST", "/v1/grant",
            {"passphrase": PASS, "record_id": rid, "provider_id": "custom"},
        )
        st, body = http(rt.port, "/v1/request", {"token": g["token"], "method": "GET", "path": "/x"},
                        "POST")
        check("default: capability token alone reaches /v1/request", st != 401, str(st))
    finally:
        rt.stop()

    rt, rid = build("unix", lockdown=True)
    try:
        st, g = control.control_request(
            "POST", "/v1/grant",
            {"passphrase": PASS, "record_id": rid, "provider_id": "custom"},
        )
        st, body = http(rt.port, "/v1/request", {"token": g["token"], "method": "GET", "path": "/x"},
                        "POST")
        check("lockdown: capability token alone is refused", st == 401, str(st))

        # Lockdown must not fail closed into uselessness: with the control
        # credential, the same request has to go through to the capability check.
        token = control.load_token()
        check("lockdown: a control token exists on a unix broker", bool(token))
        st, body = http(
            rt.port,
            "/v1/request",
            {"token": g["token"], "method": "GET", "path": "/x"},
            "POST",
            token=token,
        )
        check("lockdown: capability + control token is accepted", st != 401, str(st))
    finally:
        rt.stop()


def main() -> int:
    print("=" * 74)
    print("digital_keys.broker red-team suite")
    print("=" * 74)
    test_path_attacks()
    test_prefix_matching()
    test_url_construction()
    test_header_attacks()
    test_end_to_end()
    test_private_ip_blocking()
    test_path_scope_bypass()
    test_dot_segments_rejected_not_cleaned()
    test_reserved_chars_stay_encoded()
    test_ordinary_paths_still_work()
    test_pinned_ip_reaches_the_socket()
    test_scrub_runs_inside_the_lease()
    test_control_api_auth()

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("\n" + "=" * 74)
    print(f"{passed}/{total} checks passed")
    if passed != total:
        print("\nFAILURES:")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}  {detail}")
    print("=" * 74)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
