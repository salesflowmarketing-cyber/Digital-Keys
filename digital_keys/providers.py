"""
digital_keys.providers - the built-in catalog.

Every entry here was checked against the provider's own documentation rather
than guessed. Where a provider does something unusual - a non-Bearer auth
header, a base path that is not just the host - it is called out in `notes`,
because those are exactly the details that silently break an integration.

Verified against vendor docs while building this:
  ollama         local HTTP, usually needs NO key at all
  openrouter     https://openrouter.ai/api/v1     Bearer
  openai         https://api.openai.com/v1        Bearer
  anthropic      https://api.anthropic.com        Bearer + mandatory version header
  cerebras       https://api.cerebras.ai          Bearer, /v1/chat/completions
  mistral        https://api.mistral.ai/v1        Bearer
  huggingface    https://api-inference.huggingface.co  Bearer
  gemini         https://generativelanguage.googleapis.com  query param auth
  tavily         https://api.tavily.com          Bearer (docs show Authorization, NOT x-api-key)
  firecrawl      https://api.firecrawl.dev       Bearer fc-...
  browserbase    https://api.browserbase.com/v1  x-bb-api-key header, NOT Bearer
  nanogpt        https://api.nano-gpt.com/api/v1 Bearer
  github         https://api.github.com          Bearer token
  opencode-zen   OpenCode's gateway, base path varies by release

Anything NOT in this list is fine too: `custom` providers let the user define
their own, and the broker applies the same SSRF and destination-pinning rules
to those. Being absent from the catalog is a statement about our diligence,
not a statement that the provider is unsafe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .records import Category, Provider


def _p(
    pid: str,
    label: str,
    category: Category,
    base_url: str,
    auth_style: str = "bearer",
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    auth_query_param: str | None = None,
    extra_headers: dict[str, str] | None = None,
    allowed_path_prefixes: list[str] | None = None,
    allowed_methods: list[str] | None = None,
    notes: str = "",
) -> Provider:
    return Provider(
        id=pid,
        label=label,
        category=category,
        base_url=base_url,
        auth_style=auth_style,
        auth_header=auth_header,
        auth_prefix=auth_prefix,
        auth_query_param=auth_query_param,
        extra_headers=extra_headers or {},
        allowed_path_prefixes=allowed_path_prefixes or [],
        allowed_methods=allowed_methods or ["GET", "POST", "PUT", "PATCH", "DELETE"],
        notes=notes,
    )


CATALOG: dict[str, Provider] = {
    "ollama": _p(
        "ollama", "Ollama", Category.LLM, "http://localhost:11434",
        auth_style="none", auth_prefix="",
        notes="Local. Usually needs no credential at all. Requires --allow-private "
              "so the broker will talk to loopback.",
    ),
    "openrouter": _p(
        "openrouter", "OpenRouter", Category.LLM, "https://openrouter.ai/api/v1",
        allowed_path_prefixes=["/api/v1"],
        notes="Base path is /api/v1. Endpoints: /api/v1/chat/completions, /api/v1/models.",
    ),
    "openai": _p(
        "openai", "OpenAI", Category.LLM, "https://api.openai.com/v1",
        notes="Base path is /v1.",
    ),
    "anthropic": _p(
        "anthropic", "Anthropic (Claude)", Category.LLM, "https://api.anthropic.com",
        extra_headers={"anthropic-version": "2023-06-01", "content-type": "application/json"},
        notes="Native Messages API is POST /v1/messages, NOT OpenAI-shaped. "
              "The anthropic-version header is required on every request.",
    ),
    "gemini": _p(
        "gemini", "Gemini (Google)", Category.LLM, "https://generativelanguage.googleapis.com",
        auth_style="query", auth_query_param="key",
        notes="Uses API key as a query parameter: ?key=YOUR_KEY. "
              "Endpoints: /v1beta/models/gemini-pro:generateContent, "
              "/v1beta/models/gemini-2.0-flash:generateContent. "
              "Get keys at https://aistudio.google.com/apikey",
    ),
    "cerebras": _p(
        "cerebras", "Cerebras", Category.LLM, "https://api.cerebras.ai",
        notes="OpenAI-compatible: POST /v1/chat/completions.",
    ),
    "mistral": _p(
        "mistral", "Mistral", Category.LLM, "https://api.mistral.ai/v1",
        notes="Base path is /v1.",
    ),
    "huggingface": _p(
        "huggingface", "Hugging Face", Category.LLM, "https://api-inference.huggingface.co",
        notes="Inference router. Read tokens start 'hf_', write tokens 'hf_'.",
    ),
    "nanogpt": _p(
        "nanogpt", "NanoGPT", Category.LLM, "https://api.nano-gpt.com/api/v1",
        notes="Base path is /api/v1. OpenAI-compatible, plus an Anthropic-compatible "
              "/api/v1/messages and image/video endpoints.",
    ),
    "opencode-zen": _p(
        "opencode-zen", "OpenCode Zen", Category.LLM, "https://opencode.ai/zen/v1",
        notes="OpenCode's own gateway. Confirm the path against your installed "
              "release; it has changed between versions.",
    ),
    "tavily": _p(
        "tavily", "Tavily", Category.SEARCH, "https://api.tavily.com",
        allowed_methods=["POST"],
        notes="Auth is 'Authorization: Bearer tvly-...', per current docs - not the "
              "x-api-key header older integrations used.",
    ),
    "firecrawl": _p(
        "firecrawl", "Firecrawl", Category.SEARCH, "https://api.firecrawl.dev",
        auth_style="bearer", auth_prefix="Bearer ",
        notes="Key format fc-...  Endpoints /v1/scrape, /v1/crawl, /v1/map, /v1/search.",
    ),
    "browserbase": _p(
        "browserbase", "Browserbase", Category.BROWSER, "https://api.browserbase.com/v1",
        auth_style="header", auth_header="x-bb-api-key", auth_prefix="",
        notes="Uses the x-bb-api-key header, NOT Authorization: Bearer. Getting this "
              "wrong is the most common Browserbase integration failure.",
    ),
    "github": _p(
        "github", "GitHub", Category.DEV, "https://api.github.com",
        notes="Fine-grained PATs are strongly preferred. Scope them to what the agent "
              "actually needs; a classic PAT with 'repo' is a repo-wide key.",
    ),
}


def catalog() -> list[Provider]:
    return list(CATALOG.values())


def get(provider_id: str) -> Provider | None:
    return CATALOG.get(provider_id)


def install_into_vault(handle) -> int:
    """
    Copy the catalog into a vault. User-defined providers already in the vault
    win: we never silently overwrite something the user set up by hand.
    """
    existing = {p.id for p in handle.providers()}
    n = 0
    for p in catalog():
        if p.id in existing:
            continue
        handle.add_provider(p)
        n += 1
    return n