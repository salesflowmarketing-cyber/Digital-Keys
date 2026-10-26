"""
digital_keys.records - the in-memory data model.

These are plain dataclasses. Serialisation to disk is handled by vault.py and
goes through the AEAD layer, so nothing here needs to worry about encryption.

A note on what is and isn't sensitive:
  - `secret` is always sensitive.
  - `username` and `label` are *metadata* but they are still encrypted at rest
    (we encrypt the whole record blob, not field-by-field), because "which
    bank am I a customer of" is not something an attacker with a stolen laptop
    should learn from a hex dump.
  - Only `id` and `category` sort of need to be readable for the UI to group
    things, and we keep those out of the record blob entirely.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    LLM = "llm"
    AI_TOOL = "ai_tool"
    SEARCH = "search"
    DEV = "dev"
    BROWSER = "browser"
    CLOUD = "cloud"
    LOGIN = "login"
    FINANCE = "finance"
    SEED = "seed"
    NOTE = "note"
    CUSTOM = "custom"


class SecretKind(str, Enum):
    """How the secret should be presented / injected."""

    API_KEY = "api_key"
    PASSWORD = "password"
    SEED_PHRASE = "seed_phrase"
    OAUTH_REFRESH = "oauth_refresh"
    TOKEN = "token"
    PASSPHRASE = "passphrase"
    NOTE = "note"


# Characters that break terminal display, log files and header injection.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitise_for_header(value: str) -> str:
    """
    Make a string safe to place in an HTTP header value.

    Strips control characters (including CR/LF, which is header injection) and
    normalises unicode so that a homoglyph or zero-width char cannot smuggle a
    lookalike credential past a human doing a visual comparison.
    """
    if not isinstance(value, str):
        raise TypeError("expected str")
    cleaned = _CONTROL_RE.sub("", value)
    # Collapse zero-width and bidi-override characters.
    cleaned = "".join(
        ch
        for ch in cleaned
        if unicodedata.category(ch) not in ("Cf", "Cc", "Zl", "Zp") or ch == " "
    )
    return cleaned.strip()


@dataclass
class Record:
    """
    One vault entry.

    `provider_id` is optional: a record with no provider is a plain login, note
    or seed phrase that has no machine-to-machine use at all.
    """

    id: str
    category: Category
    kind: SecretKind
    label: str
    secret: str = ""
    username: str = ""
    provider_id: str | None = None
    notes: str = ""
    url: str = ""
    # ISO-8601 UTC, set by the vault layer.
    created_at: str = ""
    updated_at: str = ""
    # Per-record flags the user controls.
    agent_capable: bool = True
    favourite: bool = False

    def public_view(self) -> dict:
        """
        What an agent is allowed to see. Note the total absence of `secret`.
        This dict is the only shape that crosses the broker boundary.
        """
        return {
            "id": self.id,
            "label": self.label,
            "category": self.category.value,
            "kind": self.kind.value,
            "username": self.username,
            "provider_id": self.provider_id,
            "url": self.url,
            "favourite": self.favourite,
        }

    def display_with_secret(self) -> str:
        """For the human UI, and only after the user has authenticated."""
        bits = [self.label]
        if self.username:
            bits.append(self.username)
        if self.provider_id:
            bits.append(f"provider={self.provider_id}")
        return "  ".join(bits)


@dataclass
class Provider:
    """
    A destination we are willing to send a credential to.

    The security of the whole broker rests on this: `base_url` and `auth_style`
    come from the vault (user-controlled, shown in the UI) and are NEVER taken
    from an agent request. An agent may choose *which* provider to use, but the
    agent has no say in where the bytes go.
    """

    id: str
    label: str
    category: Category
    base_url: str
    auth_style: str = "bearer"  # bearer | header | query | none
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    # Where in the request the key goes, e.g. "api_key" for ?api_key=
    auth_query_param: str | None = None
    # Extra headers every request to this provider must carry.
    extra_headers: dict[str, str] = field(default_factory=dict)
    # Path prefixes an agent may reach. Empty means "only the base path".
    allowed_path_prefixes: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    # Custom providers are user-added, so they get extra scrutiny.
    is_custom: bool = False
    notes: str = ""
