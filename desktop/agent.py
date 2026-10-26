"""
Digital Keys agent client - drop this into opencode / goose / any agent runtime.

WHAT THIS IS
    A small module an agent imports to ask the human for a credential and then
    make the call itself. The agent never sees the secret. It gets a
    short-lived capability token, posts a relative path, and gets the
    provider's response back.

WHAT THE AGENT STILL CANNOT DO
    - It cannot see the key, the passphrase, or the vault file.
    - It cannot choose the destination host; that is pinned server-side.
    - It cannot mint its own token without the human typing the passphrase.
    - Its token stops working after one use (or a short TTL), and the human can
      kill every live grant with one click.

HOW TO USE
    from digital_keys import call, list_providers, request_grant

    # normal flow, human approves in their terminal
    tok = request_grant(record_id)
    result = call(tok, "POST", "/api/v1/chat/completions", body={...})

Set DIGITAL_KEYS_BROKER_URL if the broker is not on the default port.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BROKER = os.environ.get("DIGITAL_KEYS_BROKER_URL", "http://127.0.0.1:8787")


class BrokerError(Exception):
    pass


class Denied(BrokerError):
    pass


def _post(path, payload, timeout=180):
    req = urllib.request.Request(
        BROKER + path,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"error": body}
        if e.code in (400, 401, 403):
            raise Denied(parsed.get("error", f"denied ({e.code})")) from None
        raise BrokerError(f"broker returned {e.code}: {parsed.get('error', 'unknown')}") from None
    except urllib.error.URLError as e:
        raise BrokerError(
            f"cannot reach the digital_keys.broker at {BROKER} ({e.reason}). "
            "Is 'dk serve' running?"
        ) from None


def _get(path, timeout=30):
    try:
        with urllib.request.urlopen(BROKER + path, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise BrokerError(f"broker returned {e.code}") from None
    except urllib.error.URLError as e:
        raise BrokerError(
            f"cannot reach the digital_keys.broker at {BROKER} ({e.reason}). "
            "Is 'dk serve' running?"
        ) from None


def health():
    return _get("/v1/health")


def list_providers():
    """Which providers exist and which record ids can serve them. No secrets."""
    return _get("/v1/providers").get("providers", [])


def audit(limit=50):
    """
    Redacted audit tail.

    This is a control-channel route: it reveals which providers and records
    exist, so it is not reachable from the agent listener. The demo agent runs
    as the operator, so it goes through the control channel like the CLI does.
    """
    from digital_keys import control

    status, data = control.control_request("GET", f"/v1/audit?limit={limit}")
    if status != 200:
        raise BrokerError(f"broker returned {status}: {data.get('error', 'unknown')}")
    return data.get("audit", [])


def emergency_stop():
    """
    Kill every outstanding grant.

    This is a control-channel route. The demo agent runs as the operator, so it
    can trigger it; a real agent would not have the control credential and would
    have to ask the human instead.
    """
    from digital_keys import control

    status, data = control.control_request("POST", "/v1/emergency-stop", {})
    if status != 200:
        raise BrokerError(f"broker returned {status}: {data.get('error', 'unknown')}")
    return data


def request_grant(record_id: str, provider_id: str | None = None, methods=None,
                  path_prefix: str = "/", ttl: float = 300.0, single_use: bool = True,
                  port: int | None = None) -> str:
    """
    Ask the human to approve this credential. Returns a token.

    This shells out to `dk grant` so the passphrase is typed by the human
    in their own terminal, not passed through this process.
    """
    # FIX: pass the broker's real port through, otherwise this only ever works
    # on the default 8787 and fails confusingly for a custom --port.
    if port is None:
        port = int(os.environ.get("DIGITAL_KEYS_BROKER_PORT", "8787"))
    cmd = [sys.executable, "-m", "digital_keys", "grant", record_id,
           "--path-prefix", path_prefix, "--ttl", str(ttl),
           "--port", str(port)]
    if provider_id:
        cmd += ["--provider", provider_id]
    for m in (methods or []):
        cmd += ["--method", m]
    if not single_use:
        cmd += ["--reuse"]
    import subprocess

    print("The human must approve this credential use in their terminal.\n", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Denied(proc.stderr.strip() or "approval was refused or cancelled")
    return json.loads(proc.stdout)["token"]


def call(token: str, method: str, path: str, body=None, query: str = "", headers=None):
    """
    Make an authenticated request through the broker.

    `path` MUST be a relative path like '/api/v1/chat/completions'. Passing a
    full URL is rejected by the broker on purpose - that is the whole point.
    """
    status, payload = _post("/v1/request", {
        "token": token,
        "method": method.upper(),
        "path": path,
        "query": query,
        "headers": headers or {},
        "body": body,
    })
    return status, payload


def ask_human() -> str:
    """
    Interactive helper for an agent session: print what you want to do, get a
    token, make one call. Returns (status, response).
    """
    provider = input("provider id (see list_providers()): ").strip()
    path = input("path, e.g. /api/v1/chat/completions: ").strip()
    method = input("method [POST]: ").strip().upper() or "POST"
    rid = input("record id: ").strip()
    body_raw = input("JSON body (blank for {}): ").strip()
    body = json.loads(body_raw) if body_raw else {}
    tok = request_grant(rid, provider_id=provider, methods=[method],
                        path_prefix=path.rsplit("/", 1)[0] or "/")
    return call(tok, method, path, body=body)


if __name__ == "__main__":
    print(json.dumps(health(), indent=2))
    for p in list_providers():
        recs = ", ".join(f"{r['id'][:8]}={r['label']}" for r in p.get("records", [])) or "(no credential stored)"
        print(f"{p['id']:14} {p['base_url']}\n{'':14} -> {recs}")
