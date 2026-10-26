"""
digital_keys.cli - the human side.

Everything here requires the vault passphrase interactively. Nothing in this
file prints a secret by default; revealing one is a separate, explicit command
that shows the secret in cleartext with a warning, because for autofill and
copy-to-clipboard you genuinely do need to get the value out.

Commands are deliberately small and composable so they can be scripted:

  dk init
  dk add --label "OpenRouter" --provider openrouter --kind api_key
  dk list
  dk providers
  dk grant <record-id> --provider openrouter --once
  dk serve --port 8787
  dk stop
  dk audit
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import providers as catalog_mod
from .broker import BrokerConfig, Denied, Dispatcher
from .records import Category, Record, SecretKind
from .vault import InvalidPassphrase, Vault

DEFAULT_VAULT = os.path.expanduser("~/.local/share/digital-keys/vault.json")


def vault_path(args) -> str:
    if getattr(args, "vault", None):
        return os.path.expanduser(args.vault)
    env = os.environ.get("DIGITAL_KEYS_PATH") or os.environ.get("HIGHLINE_VAULT_PATH")
    if env:
        return os.path.expanduser(env)
    return DEFAULT_VAULT


def ask_passphrase(prompt: str = "Vault passphrase: ") -> str:
    pw = (
        os.environ.get("DIGITAL_KEYS_PASSPHRASE")
        or os.environ.get("HIGHLINE_VAULT_PASSPHRASE")
        or ""
    )
    if pw:
        return pw
    return getpass.getpass(prompt)


def open_vault(args):
    v = Vault(vault_path(args))
    if not v.exists():
        print(f"No vault at {v.path}. Run 'dk init' first.", file=sys.stderr)
        raise SystemExit(2)
    # Fail early and clearly on a pre-2.0 vault instead of at unlock time.
    try:
        with open(v.path, "r", encoding="utf-8") as fh:
            fmt = json.load(fh).get("format")
    except (OSError, ValueError):
        fmt = None
    if fmt in ("highline-vault", "hlv-vault"):
        print(
            "This vault was written by Highline Vault 1.x. Digital Keys 2.0 changed the "
            "key-derivation labels, so it cannot be opened. Create a new vault with "
            "'dk init --vault <new-path>' and re-add your credentials.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return v


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_init(args) -> int:
    path = vault_path(args)
    if os.path.exists(path) and not args.force:
        print(f"{path} already exists. Use --force to replace it.", file=sys.stderr)
        return 2
    if args.force and os.path.exists(path):
        os.rename(path, path + ".bak")
        print(f"Existing vault moved to {path}.bak")

    # Allow passphrase from env var or --passphrase
    first = args.passphrase or os.environ.get("DIGITAL_KEYS_PASSPHRASE") or ""
    if first:
        second = first
    else:
        first = ask_passphrase("Create vault passphrase: ")
        second = ask_passphrase("Confirm passphrase: ")
    if first != second:
        print("Passphrases did not match.", file=sys.stderr)
        return 2
    if len(first) < 12:
        print("Use at least 12 characters. A short passphrase is the weak link.", file=sys.stderr)
        return 2
    v = Vault.create(path, first)
    with v.unlock(first) as h:
        n = catalog_mod.install_into_vault(h)
    print(f"Vault created at {path}")
    print(f"Installed {n} built-in providers. Add credentials with 'dk add'.")
    return 0


def cmd_providers(args) -> int:
    v = open_vault(args)
    passphrase = ask_passphrase()
    try:
        with v.unlock(passphrase) as h:
            for p in sorted(h.providers(), key=lambda x: (x.category.value, x.label)):
                tag = " [custom]" if p.is_custom else ""
                print(f"\n{p.id}{tag}")
                print(f"  name    : {p.label}  ({p.category.value})")
                print(f"  base    : {p.base_url}")
                print(f"  auth    : {p.auth_style}"
                      + (f" via {p.auth_header}" if p.auth_header != "Authorization" else ""))
                if p.notes:
                    print(f"  notes   : {p.notes}")
    except InvalidPassphrase:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    return 0


def cmd_add(args) -> int:
    v = open_vault(args)
    passphrase = ask_passphrase()
    secret = args.secret
    if not secret:
        secret = getpass.getpass("Secret (input hidden): ")
    if not secret:
        print("Empty secret not stored.", file=sys.stderr)
        return 2
    try:
        kind = SecretKind(args.kind)
        category = Category(args.category)
    except ValueError as exc:
        print(f"{exc}. Valid kinds: {[k.value for k in SecretKind]}", file=sys.stderr)
        return 2
    try:
        with v.unlock(passphrase) as h:
            rec = Record(
                id="",
                category=category,
                kind=kind,
                label=args.label,
                secret=secret,
                username=args.username or "",
                provider_id=args.provider,
                notes=args.notes or "",
                url=args.url or "",
                agent_capable=not args.no_agent,
            )
            # FIX: validate the provider BEFORE writing, so a typo like
            # --provider openrower can never leave a dangling record behind.
            if args.provider:
                h.provider(args.provider)  # raises KeyError -> nothing written
            saved = h.put(rec)
    except InvalidPassphrase:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(f"Unknown provider: {exc}", file=sys.stderr)
        return 2
    print(f"Stored {saved.id}  ({saved.label})")
    return 0


def cmd_list(args) -> int:
    v = open_vault(args)
    passphrase = ask_passphrase()
    try:
        with v.unlock(passphrase) as h:
            recs = h.records()
            if not recs:
                print("Vault is empty.")
                return 0
            for r in recs:
                star = "*" if r.favourite else " "
                agent = " " if r.agent_capable else "-"
                prov = r.provider_id or "-"
                print(f"{star}{agent} {r.id[:8]}  {r.label:<28} {r.kind.value:<13} {prov:<14} {r.username}")
            print("\n(* favourite, - not usable by agents)")
    except InvalidPassphrase:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    return 0


def cmd_show(args) -> int:
    v = open_vault(args)
    passphrase = ask_passphrase()
    try:
        with v.unlock(passphrase) as h:
            r = h.get(args.record)
            print(f"label    : {r.label}")
            print(f"kind     : {r.kind.value}")
            print(f"category : {r.category.value}")
            print(f"provider : {r.provider_id or '-'}")
            print(f"username : {r.username or '-'}")
            print(f"url      : {r.url or '-'}")
            print(f"agent    : {'yes' if r.agent_capable else 'no'}")
            if r.notes:
                print(f"notes    : {r.notes}")
            if args.reveal:
                print(f"\nsecret   : {r.secret}")
            else:
                print(f"\nsecret   : [hidden - use --reveal to print it]")
    except InvalidPassphrase:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(exc, file=sys.stderr)
        return 2
    return 0


def cmd_approve(args) -> int:
    """
    The human approves one agent request. This issues a single-use capability
    and prints it. In the real desktop app this is driven by a GUI dialog; on
    the CLI it is an explicit command so it can be driven from a script.
    """
    v = open_vault(args)
    passphrase = ask_passphrase()
    try:
        with v.unlock(passphrase) as h:
            rec = h.get(args.record)
            if not rec.agent_capable:
                print("That record is marked not-for-agents.", file=sys.stderr)
                return 2
            prov = h.provider(args.provider or rec.provider_id or "")
    except InvalidPassphrase:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(exc, file=sys.stderr)
        return 2
    # FIX: --reuse actually controls single-use now (it was silently ignored)
    args.single_use = not args.reuse
    return _grant_via_running_broker(args, passphrase, rec.id, prov.id)


def _grant_via_running_broker(args, passphrase, record_id, provider_id) -> int:
    """
    Ask the *running* broker to mint a capability, so the token and the
    server's capability store are the same object. A token minted in a
    throwaway process would be useless, and quietly returning one would be
    worse than refusing.

    The call goes over the control channel, which on POSIX is a 0600 Unix
    socket verified by peer UID. That keeps the vault passphrase off the TCP
    stack entirely on Linux.
    """
    from . import control

    payload = {
        "passphrase": passphrase,
        "record_id": record_id,
        "provider_id": provider_id,
        "methods": args.method or ["GET", "POST"],
        "path_prefix": args.path_prefix,
        "ttl": args.ttl,
        "label": args.label or f"cli:{record_id[:8]}",
        "single_use": args.single_use,
    }
    try:
        status, out = control.control_request("POST", "/v1/grant", payload, port=args.port)
    except Exception as exc:
        print(f"Could not reach a broker: {exc}", file=sys.stderr)
        print("Start one with 'dk serve' first.", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Broker refused the grant ({status}): {out.get('error', out)}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    print("\nGive the agent this token, never the vault passphrase.", file=sys.stderr)
    return 0


def cmd_serve(args) -> int:
    """
    Run the broker.

    Two listeners start together: the agent listener on TCP loopback, and the
    control listener on a peer-UID-verified Unix socket (or TCP + bearer token
    where the kernel cannot report a peer identity).

    NOTE: in this reference implementation the passphrase is read from the
    environment so the process can serve requests unattended. That is honest
    but it is NOT the final product: the desktop build prompts per request and
    holds no passphrase at all. See docs/THREAT_MODEL.md.
    """
    from . import control
    from .server import BrokerRuntime

    # Line-buffer so 'dk serve > log' shows the startup banner immediately.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    v = open_vault(args)
    passphrase = ask_passphrase("Vault passphrase (held for this session): ")

    def unlock_fn() -> str:
        return passphrase

    cfg = BrokerConfig(
        vault_path=v.path,
        unlock_fn=unlock_fn,
        allow_private_for_custom=args.allow_private,
    )
    try:
        runtime = BrokerRuntime(
            cfg,
            unlock_fn,
            host=args.host,
            port=args.port,
            control_transport=args.control_transport,
            lockdown=args.lockdown,
        )
    except Denied as exc:
        print(f"Cannot start broker: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"Cannot start broker on {args.host}:{args.port}: {exc.strerror or exc}",
            file=sys.stderr,
        )
        print("Another broker may already be running, or the port is in use.", file=sys.stderr)
        return 1

    runtime.start()
    print(f"dk broker listening on {runtime.agent_url}")
    print("Agent routes : /v1/health /v1/providers /v1/request")
    print("Control      : /v1/grant /v1/emergency-stop /v1/pending /v1/audit")
    print(f"  {control.describe(runtime.control_mode)}")
    if args.lockdown:
        print(
            "  LOCKDOWN: /v1/request also requires the control credential. "
            "Agents will need it too.",
            file=sys.stderr,
        )
    print("This service is local-only. Press Ctrl-C to stop.")

    # Close the listeners on SIGTERM as well as Ctrl-C, so the control socket
    # does not survive as a stale file when the process is killed politely.
    import signal
    import threading

    stop_event = threading.Event()

    def _on_signal(signum, frame):  # noqa: ARG001
        stop_event.set()

    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[sig] = signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass
    try:
        while not stop_event.wait(0.5):
            pass
        print("\nstopped")
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        runtime.stop()
    return 0


def cmd_token(args) -> int:
    """Show or rotate the control token (TCP control channel only)."""
    from . import control

    if args.action == "show":
        if control.unix_control_supported() and control.socket_path().exists():
            print(
                "This broker uses the Unix control socket, which is verified by "
                f"peer UID ({control.socket_path()}). There is no token to show.",
                file=sys.stderr,
            )
            return 0
        token = control.load_token()
        if not token:
            print("No control token. Is a broker running?", file=sys.stderr)
            return 1
        print(token)
        return 0
    if args.action == "rotate":
        try:
            status, out = control.control_request("POST", "/v1/token/rotate", {}, port=args.port)
        except Exception as exc:
            print(f"Could not reach a broker: {exc}", file=sys.stderr)
            return 1
        if status != 200:
            print(f"Broker refused rotation ({status}): {out.get('error', out)}", file=sys.stderr)
            return 1
        print(f"Rotated. New token: {out.get('token')}")
        return 0
    print(f"Unknown action {args.action!r}", file=sys.stderr)
    return 2


def cmd_stop(args) -> int:
    from . import control

    try:
        status, out = control.control_request("POST", "/v1/emergency-stop", {}, port=args.port)
    except Exception as exc:
        print(f"Could not reach a broker: {exc}", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Broker refused ({status}): {out.get('error', out)}", file=sys.stderr)
        return 1
    print(json.dumps(out))
    return 0


def cmd_audit(args) -> int:
    from . import control

    try:
        status, data = control.control_request("GET", f"/v1/audit?limit={args.limit}", port=args.port)
    except Exception as exc:
        print(f"Could not reach a broker: {exc}", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Broker refused ({status}): {data.get('error', data)}", file=sys.stderr)
        return 1
    for e in data.get("audit", []):
        print(json.dumps(e))
    return 0


def cmd_delete(args) -> int:
    """Delete a credential from the vault."""
    v = open_vault(args)
    passphrase = ask_passphrase()
    try:
        with v.unlock(passphrase) as h:
            try:
                rec = h.get(args.record)
            except KeyError:
                print(f"No record with id {args.record!r}", file=sys.stderr)
                return 2
            h.delete(args.record)
            print(f"Deleted {rec.label} ({args.record[:8]})")
    except InvalidPassphrase:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    return 0


def cmd_gui(args) -> int:
    """Launch the native desktop GUI."""
    from .gui import run_gui
    run_gui()
    return 0


def cmd_selftest(args) -> int:
    from .vault import Vault
    import tempfile


    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "v.json")
        v = Vault.create(p, "selftest passphrase 12345")
        with v.unlock("selftest passphrase 12345") as h:
            n = catalog_mod.install_into_vault(h)
            h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                         label="t", secret="s3cr3t-value", provider_id="openrouter"))
        with open(p, "r") as fh:
            raw = fh.read()
        leaked = [k for k in ("s3cr3t-value", "openrouter", "t") if f'"{k}"' in raw]
        print(f"vault round-trip ok; {n} providers installed; file mode "
              f"{oct(os.stat(p).st_mode & 0o777)}")
        print("plaintext scan:", "CLEAN" if not leaked else f"LEAKED {leaked}")
        return 0 if not leaked else 1


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dk", description="Digital Keys - encrypted credential vault and AI agent broker.")
    p.add_argument("--vault", help="path to vault file (default: $DIGITAL_KEYS_PATH or ~/.local/share/digital-keys/vault.json)")
    sub = p.add_subparsers(dest="cmd", required=True)

    si = sub.add_parser("init", help="create a new vault")
    si.add_argument("--force", action="store_true")
    si.add_argument("--passphrase", help="passphrase (omit to be prompted)")
    si.set_defaults(func=cmd_init)

    sp = sub.add_parser("providers", help="list providers")
    sp.set_defaults(func=cmd_providers)

    sa = sub.add_parser("add", help="add or update a credential")
    sa.add_argument("--label", required=True)
    sa.add_argument("--provider")
    sa.add_argument("--kind", default="api_key")
    sa.add_argument("--category", default="custom")
    sa.add_argument("--username")
    sa.add_argument("--secret", help="skip the hidden prompt; visible in shell history")
    sa.add_argument("--url")
    sa.add_argument("--notes")
    sa.add_argument("--no-agent", action="store_true", help="never let agents use this")
    sa.set_defaults(func=cmd_add)

    sl = sub.add_parser("list", help="list records")
    sl.set_defaults(func=cmd_list)

    ss = sub.add_parser("show", help="show one record")
    ss.add_argument("record")
    ss.add_argument("--reveal", action="store_true", help="print the secret in cleartext")
    ss.set_defaults(func=cmd_show)

    sg = sub.add_parser("grant", help="approve an agent request and mint a one-time token")
    sg.add_argument("record")
    sg.add_argument("--provider")
    sg.add_argument("--method", action="append")
    sg.add_argument("--path-prefix", default="/")
    sg.add_argument("--ttl", type=float, default=300.0)
    sg.add_argument("--label")
    sg.add_argument("--reuse", action="store_true", help="allow more than one use (off by default)")
    sg.add_argument("--port", type=int, default=None, help="control port override (default: discovered)")
    sg.set_defaults(func=cmd_approve)

    sv = sub.add_parser("serve", help="run the broker")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8787)
    sv.add_argument("--allow-private", action="store_true",
                    help="permit loopback/private destinations (needed for Ollama)")
    sv.add_argument(
        "--control-transport",
        choices=("auto", "unix", "tcp"),
        default="auto",
        help="how the human control channel is reached (default: unix on POSIX, tcp elsewhere)",
    )
    sv.add_argument(
        "--lockdown",
        action="store_true",
        help=(
            "ALSO require the control credential on /v1/request. Breaks the "
            "'agent holds one short-lived token' guarantee: agents must be given "
            "a long-lived secret. Off by default."
        ),
    )
    sv.set_defaults(func=cmd_serve)

    stok = sub.add_parser("token", help="show or rotate the control token (tcp control channel)")
    stok.add_argument("action", choices=("show", "rotate"))
    stok.add_argument("--port", type=int, default=None, help="control port override (default: discovered)")
    stok.set_defaults(func=cmd_token)

    sst = sub.add_parser("stop", help="revoke every outstanding grant")
    sst.add_argument("--port", type=int, default=None, help="control port override (default: discovered)")
    sst.set_defaults(func=cmd_stop)

    sa2 = sub.add_parser("audit", help="print the redacted audit tail")
    sa2.add_argument("--port", type=int, default=None, help="control port override (default: discovered)")
    sa2.add_argument("--limit", type=int, default=50)
    sa2.set_defaults(func=cmd_audit)

    sdel = sub.add_parser("delete", help="delete a credential")
    sdel.add_argument("record")
    sdel.set_defaults(func=cmd_delete)

    sgui = sub.add_parser("gui", help="launch the native desktop GUI")
    sgui.set_defaults(func=cmd_gui)

    st = sub.add_parser("selftest", help="quick crypto + leakage check")
    st.set_defaults(func=cmd_selftest)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
