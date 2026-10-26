"""
Digital Keys - Native Desktop GUI

A proper desktop application built with CustomTkinter that looks and feels
like a native Linux app. Manages credentials (API keys, passwords, etc.)
in an encrypted local vault.

No confusing buttons. Just credentials management.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

import customtkinter as ctk

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(HERE)

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BUTTON_COLOR = "#1f6feb"
BUTTON_HOVER = "#388bfd"
DANGER_COLOR = "#da3633"
DANGER_HOVER = "#f85149"
SUCCESS_COLOR = "#238636"
SUCCESS_HOVER = "#2ea043"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cli(*args: str, input_str: str = "", vault_path: str = "") -> tuple[int, str, str]:
    """Run a digital-keys CLI command."""
    cmd = [sys.executable, "-m", "digital_keys"] + list(args)
    env = {**os.environ}
    if vault_path:
        env["DIGITAL_KEYS_PATH"] = vault_path
    try:
        proc = subprocess.run(
            cmd, input=input_str, capture_output=True, text=True, timeout=60, env=env
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _get_passphrase() -> str:
    """Get the vault passphrase from env or prompt."""
    pw = (
        os.environ.get("DIGITAL_KEYS_PASSPHRASE")
        or os.environ.get("HIGHLINE_VAULT_PASSPHRASE")
        or ""
    )
    if pw:
        return pw
    return ""


def _default_vault_path() -> str:
    return (
        os.environ.get("DIGITAL_KEYS_PATH")
        or os.environ.get("HIGHLINE_VAULT_PATH")
        or os.path.expanduser("~/.local/share/digital-keys/vault.json")
    )


# ---------------------------------------------------------------------------
# DigitalKeysApp
# ---------------------------------------------------------------------------


class DigitalKeysApp(ctk.CTk):
    """Main native desktop application window."""

    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Digital Keys")
        self.geometry("880x640")
        self.minsize(720, 540)

        # State
        self.vault_path = _default_vault_path()
        self._passphrase_cache = _get_passphrase()

        # Ensure vault directory exists
        os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)

        # Build the UI first
        self._build_ui()

        # Set window icon after UI is ready (scheduled so window exists)
        self.after(100, self._set_icon)

        # Load data after UI is shown
        self.after(300, self._initial_load)

    # ======================================================================
    # UI Build
    # ======================================================================

    def _set_icon(self):
        """Set the window icon from the Highline logo.
        
        Uses multiple strategies since different Linux DEs handle
        window icons differently. Stored as instance attr to prevent GC.
        """
        static = os.path.join(HERE, "static")
        self._icon_photo = None

        # Strategy 1: iconphoto with PhotoImage from PIL (most reliable on Linux)
        for src in [
            os.path.join(static, "icon.png"),
            os.path.join(static, "icon_128.png"),
            os.path.expanduser("~/.local/share/icons/hicolor/128x128/apps/digital-keys.png"),
        ]:
            if os.path.exists(src):
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(src)
                    self._icon_photo = ImageTk.PhotoImage(img)
                    self.iconphoto(True, self._icon_photo)
                    self.wm_iconphoto(True, self._icon_photo)
                    return
                except Exception:
                    continue

        # Strategy 2: iconbitmap with .ico (works on some X11 WMs)
        for src in [
            os.path.join(static, "icon.ico"),
        ]:
            if os.path.exists(src):
                try:
                    self.iconbitmap(default=src)
                    return
                except Exception:
                    continue

    def _build_ui(self):
        """Build the complete native UI."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # -- Header --
        header = ctk.CTkFrame(self, height=52, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        self.logo = ctk.CTkLabel(
            header, text="🔑  Digital Keys",
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="w",
        )
        self.logo.grid(row=0, column=0, padx=(16, 8), pady=10)

        # Vault status indicator
        self.status_light = ctk.CTkLabel(header, text="●", font=ctk.CTkFont(size=16))
        self.status_light.grid(row=0, column=1, sticky="e")
        self.status_light.configure(text_color="#d29922")

        self.status_text = ctk.CTkLabel(
            header, text="initializing...",
            font=ctk.CTkFont(size=12),
            text_color=("#666666", "#999999"),
        )
        self.status_text.grid(row=0, column=2, padx=(4, 16), pady=10)

        # -- Tab bar --
        tab_frame = ctk.CTkFrame(self, height=34, corner_radius=0)
        tab_frame.grid(row=1, column=0, sticky="ew", pady=(0, 2))
        tab_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.tab_buttons: dict[str, ctk.CTkButton] = {}
        tabs = [
            ("dashboard", "📊  Dashboard"),
            ("credentials", "🔐  Credentials"),
            ("add", "➕  Add"),
            ("custom", "🛠  Custom"),
            ("about", "ℹ️  About"),
        ]
        for i, (key, label) in enumerate(tabs):
            btn = ctk.CTkButton(
                tab_frame, text=label,
                font=ctk.CTkFont(size=12),
                height=28, corner_radius=6,
                command=lambda k=key: self._switch_tab(k),
                fg_color="transparent",
                text_color=("#555555", "#AAAAAA"),
                hover_color=("#DDDDDD", "#333333"),
            )
            btn.grid(row=0, column=i, padx=1, pady=3, sticky="ew")
            self.tab_buttons[key] = btn
        self.tab_buttons["dashboard"].configure(fg_color=("#1f6feb", "#1a3a5c"), text_color="white")

        # -- Content area --
        content = ctk.CTkFrame(self, corner_radius=0)
        content.grid(row=2, column=0, sticky="nsew", padx=6, pady=(0, 6))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)

        self.frames: dict[str, ctk.CTkScrollableFrame] = {}
        for key in ("dashboard", "credentials", "add", "custom", "about"):
            frame = ctk.CTkScrollableFrame(content, corner_radius=8)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_columnconfigure(0, weight=1)
            self.frames[key] = frame

        self._build_dashboard()
        self._build_credentials()
        self._build_add()
        self._build_custom()
        self._build_about()
        self._show_frame("dashboard")

        # -- Status bar --
        statusbar = ctk.CTkFrame(self, height=28, corner_radius=0)
        statusbar.grid(row=3, column=0, sticky="ew")
        statusbar.grid_columnconfigure(0, weight=1)

        self.statusbar = ctk.CTkLabel(
            statusbar, text="Ready",
            font=ctk.CTkFont(size=11), anchor="w",
        )
        self.statusbar.grid(row=0, column=0, padx=12, pady=3, sticky="w")

        self.refresh_btn = ctk.CTkButton(
            statusbar, text="⟳  Refresh", font=ctk.CTkFont(size=11),
            width=90, height=22, command=self._refresh_all,
        )
        self.refresh_btn.grid(row=0, column=1, padx=4, pady=3)

    # ======================================================================
    # Tab switching
    # ======================================================================

    def _switch_tab(self, key: str):
        for k, btn in self.tab_buttons.items():
            if k == key:
                btn.configure(fg_color=("#1f6feb", "#1a3a5c"), text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=("#555555", "#AAAAAA"))
        self._show_frame(key)

    def _show_frame(self, key: str):
        for k, f in self.frames.items():
            if k == key:
                f.grid()
            else:
                f.grid_remove()

    # ======================================================================
    # DASHBOARD
    # ======================================================================

    def _build_dashboard(self):
        f = self.frames["dashboard"]

        # Welcome header
        ctk.CTkLabel(
            f, text="Welcome to Digital Keys",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", pady=(4, 2))

        ctk.CTkLabel(
            f, text="Your encrypted credential vault for API keys, passwords, and secrets.",
            font=ctk.CTkFont(size=13),
            text_color=("#666666", "#999999"),
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(0, 16))

        # Stats row
        stats = ctk.CTkFrame(f, corner_radius=8)
        stats.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        stats.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.stats: dict[str, ctk.CTkLabel] = {}
        for i, (label, key) in enumerate([
            ("Credentials", "creds"),
            ("Providers", "provs"),
            ("Categories", "cats"),
            ("Status", "vstatus"),
        ]):
            box = ctk.CTkFrame(stats, corner_radius=8)
            box.grid(row=0, column=i, padx=6, pady=10, sticky="nsew")

            ctk.CTkLabel(
                box, text=label,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=("#666666", "#999999"),
            ).pack(pady=(8, 0))

            val = ctk.CTkLabel(box, text="...", font=ctk.CTkFont(size=28, weight="bold"))
            val.pack(pady=(0, 8))
            self.stats[key] = val

        # Quick actions
        ctk.CTkLabel(
            f, text="Quick Actions",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        ).grid(row=3, column=0, sticky="w", pady=(0, 8))

        actions = ctk.CTkFrame(f, corner_radius=8)
        actions.grid(row=4, column=0, sticky="ew", pady=(0, 16))
        actions.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(
            actions, text="➕  Add Credential",
            font=ctk.CTkFont(size=13), height=40,
            fg_color=BUTTON_COLOR, hover_color=BUTTON_HOVER,
            command=lambda: self._switch_tab("add"),
        ).grid(row=0, column=0, padx=8, pady=12, sticky="ew")

        ctk.CTkButton(
            actions, text="🛠  Custom Provider",
            font=ctk.CTkFont(size=13), height=40,
            fg_color=BUTTON_COLOR, hover_color=BUTTON_HOVER,
            command=lambda: self._switch_tab("custom"),
        ).grid(row=0, column=1, padx=8, pady=12, sticky="ew")

        ctk.CTkButton(
            actions, text="⟳  Refresh All",
            font=ctk.CTkFont(size=13), height=40,
            fg_color="transparent",
            text_color=("#555555", "#AAAAAA"),
            hover_color=("#DDDDDD", "#333333"),
            command=self._refresh_all,
        ).grid(row=0, column=2, padx=8, pady=12, sticky="ew")

        # Recent credentials
        ctk.CTkLabel(
            f, text="Recently Added",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        ).grid(row=5, column=0, sticky="w", pady=(0, 6))

        self.recent_frame = ctk.CTkFrame(f, corner_radius=6)
        self.recent_frame.grid(row=6, column=0, sticky="ew", pady=(0, 8))
        self.recent_frame.grid_columnconfigure(0, weight=1)

        self.recent_label = ctk.CTkLabel(
            self.recent_frame, text="No credentials yet. Click 'Add Credential' to get started.",
            font=ctk.CTkFont(size=12), anchor="w",
        )
        self.recent_label.grid(row=0, column=0, padx=12, pady=10, sticky="w")

        # Tips box
        tips = ctk.CTkFrame(f, corner_radius=6)
        tips.grid(row=7, column=0, sticky="ew", pady=(8, 4))
        tips.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            tips, text="💡 Tips",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=12, pady=(8, 2), sticky="w")

        tips_text = (
            "• Use the 'Credentials' tab to browse, search, and copy your keys\n"
            "• Click 👁 to reveal a secret and copy it to clipboard\n"
            "• Use 'Add' to store a new API key from any provider\n"
            "• Use 'Custom' to add a provider not in the built-in list\n"
            "• Set DIGITAL_KEYS_PASSPHRASE env var to skip passphrase prompts"
        )
        ctk.CTkLabel(
            tips, text=tips_text,
            font=ctk.CTkFont(size=12),
            text_color=("#666666", "#999999"),
            anchor="w", justify="left",
        ).grid(row=1, column=0, padx=12, pady=(0, 8), sticky="w")

    # ======================================================================
    # CREDENTIALS TAB
    # ======================================================================

    def _build_credentials(self):
        f = self.frames["credentials"]

        # Header row
        hdr = ctk.CTkFrame(f, corner_radius=6, height=44)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            hdr, text="Your Credentials",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=12, pady=8, sticky="w")

        # Search
        self.search_entry = ctk.CTkEntry(
            hdr, placeholder_text="🔍  Search...",
            font=ctk.CTkFont(size=13), width=200,
        )
        self.search_entry.grid(row=0, column=1, padx=4, pady=6, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._refresh_credentials())

        ctk.CTkButton(
            hdr, text="➕", font=ctk.CTkFont(size=15),
            width=32, height=28,
            command=lambda: self._switch_tab("add"),
        ).grid(row=0, column=2, padx=(4, 8), pady=6)

        # Credentials list
        self.creds_container = ctk.CTkFrame(f, corner_radius=6)
        self.creds_container.grid(row=1, column=0, sticky="nsew", pady=(0, 4))
        self.creds_container.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(1, weight=1)

    # ======================================================================
    # ADD TAB
    # ======================================================================

    def _build_add(self):
        f = self.frames["add"]

        ctk.CTkLabel(
            f, text="Add a New Credential",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", pady=(4, 2))

        ctk.CTkLabel(
            f, text="Select a provider and enter your API key or secret.",
            font=ctk.CTkFont(size=12),
            text_color=("#666666", "#999999"),
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        # Mode: Preset vs Manual
        mode_frame = ctk.CTkFrame(f, corner_radius=6)
        mode_frame.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        mode_frame.grid_columnconfigure((0, 1), weight=1)

        self.add_mode = ctk.StringVar(value="preset")
        ctk.CTkRadioButton(
            mode_frame, text="📋  Preset Provider", variable=self.add_mode,
            value="preset", font=ctk.CTkFont(size=12),
            command=self._toggle_add_mode,
        ).grid(row=0, column=0, padx=12, pady=10)
        ctk.CTkRadioButton(
            mode_frame, text="✏️  Manual Entry", variable=self.add_mode,
            value="manual", font=ctk.CTkFont(size=12),
            command=self._toggle_add_mode,
        ).grid(row=0, column=1, padx=12, pady=10)

        # Form
        form = ctk.CTkFrame(f, corner_radius=6)
        form.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        # Row 0: Provider selector
        ctk.CTkLabel(form, text="Provider:", font=ctk.CTkFont(size=12),
                     anchor="w").grid(row=0, column=0, padx=(12, 4), pady=6, sticky="w")
        self.provider_combo = ctk.CTkComboBox(
            form, values=["Loading..."], width=350,
            font=ctk.CTkFont(size=12), state="readonly",
        )
        self.provider_combo.grid(row=0, column=1, padx=(4, 12), pady=6, sticky="ew")

        self.provider_entry = ctk.CTkEntry(
            form, placeholder_text="e.g. my-custom-service",
            font=ctk.CTkFont(size=12), state="disabled",
        )
        self.provider_entry.grid(row=0, column=1, padx=(4, 12), pady=6, sticky="ew")

        # Row 1: Label
        ctk.CTkLabel(form, text="Label:", font=ctk.CTkFont(size=12),
                     anchor="w").grid(row=1, column=0, padx=(12, 4), pady=6, sticky="w")
        self.label_entry = ctk.CTkEntry(
            form, placeholder_text="e.g. My OpenAI Key", font=ctk.CTkFont(size=12),
        )
        self.label_entry.grid(row=1, column=1, padx=(4, 12), pady=6, sticky="ew")

        # Row 2: Secret
        ctk.CTkLabel(form, text="Secret:", font=ctk.CTkFont(size=12),
                     anchor="w").grid(row=2, column=0, padx=(12, 4), pady=6, sticky="w")

        secret_row = ctk.CTkFrame(form, fg_color="transparent")
        secret_row.grid(row=2, column=1, padx=(4, 12), pady=6, sticky="ew")
        secret_row.grid_columnconfigure(0, weight=1)

        self.secret_entry = ctk.CTkEntry(
            secret_row, placeholder_text="sk-...", font=ctk.CTkFont(size=12), show="*",
        )
        self.secret_entry.grid(row=0, column=0, sticky="ew")

        self.show_check = ctk.CTkCheckBox(
            secret_row, text="Show", font=ctk.CTkFont(size=11),
            command=self._toggle_secret,
        )
        self.show_check.grid(row=0, column=1, padx=(6, 0))

        # Row 3: Kind & Category
        kc = ctk.CTkFrame(form, fg_color="transparent")
        kc.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=6)
        kc.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkLabel(kc, text="Kind:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, sticky="w")
        self.kind_combo = ctk.CTkComboBox(
            kc, values=["api_key", "password", "token", "passphrase", "note"],
            font=ctk.CTkFont(size=12), width=130,
        )
        self.kind_combo.grid(row=1, column=0, sticky="w", pady=(0, 6))

        ctk.CTkLabel(kc, text="Category:", font=ctk.CTkFont(size=12)).grid(row=0, column=2, sticky="w")
        self.cat_combo = ctk.CTkComboBox(
            kc, values=["llm", "ai_tool", "search", "dev", "browser", "cloud", "login", "custom"],
            font=ctk.CTkFont(size=12), width=130,
        )
        self.cat_combo.grid(row=1, column=2, sticky="w", pady=(0, 6))

        # Save button
        self.save_btn = ctk.CTkButton(
            f, text="💾  Save Credential",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=BUTTON_COLOR, hover_color=BUTTON_HOVER,
            height=36, width=200,
            command=self._save_credential,
        )
        self.save_btn.grid(row=4, column=0, pady=12)

        self.save_status = ctk.CTkLabel(f, text="", font=ctk.CTkFont(size=12))
        self.save_status.grid(row=5, column=0, sticky="w")

        self._toggle_add_mode()

    def _toggle_add_mode(self):
        mode = self.add_mode.get()
        if mode == "preset":
            self.provider_combo.grid()
            self.provider_entry.grid_remove()
            self.provider_combo.configure(state="readonly")
            self.provider_entry.configure(state="disabled")
        else:
            self.provider_combo.grid_remove()
            self.provider_entry.grid()
            self.provider_combo.configure(state="disabled")
            self.provider_entry.configure(state="normal")

    def _toggle_secret(self):
        show = self.show_check.get() == 1
        self.secret_entry.configure(show="" if show else "*")

    # ======================================================================
    # CUSTOM PROVIDER TAB
    # ======================================================================

    def _build_custom(self):
        f = self.frames["custom"]

        ctk.CTkLabel(
            f, text="Create a Custom Provider",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", pady=(4, 2))

        ctk.CTkLabel(
            f, text="Add any service as a provider — great for APIs not in the built-in list.",
            font=ctk.CTkFont(size=12),
            text_color=("#666666", "#999999"),
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        form = ctk.CTkFrame(f, corner_radius=6)
        form.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        rows = [
            (0, "Provider ID:", "cp_id", "e.g. my-service (no spaces)"),
            (1, "Display Name:", "cp_name", "e.g. My Service"),
            (2, "Base URL:", "cp_url", "https://api.example.com/v1"),
        ]
        self.cp = {}
        for row, label, key, placeholder in rows:
            ctk.CTkLabel(form, text=label, font=ctk.CTkFont(size=12),
                         anchor="w").grid(row=row, column=0, padx=(12, 4), pady=6, sticky="w")
            w = ctk.CTkEntry(form, placeholder_text=placeholder, font=ctk.CTkFont(size=12))
            w.grid(row=row, column=1, padx=(4, 12), pady=6, sticky="ew")
            self.cp[key] = w

        # Auth style
        ctk.CTkLabel(form, text="Auth Style:", font=ctk.CTkFont(size=12),
                     anchor="w").grid(row=3, column=0, padx=(12, 4), pady=6, sticky="w")
        self.cp_auth = ctk.CTkComboBox(
            form, values=["bearer", "header", "query", "none"],
            font=ctk.CTkFont(size=12), width=150,
        )
        self.cp_auth.grid(row=3, column=1, padx=(4, 12), pady=6, sticky="w")

        ctk.CTkLabel(form, text="Category:", font=ctk.CTkFont(size=12),
                     anchor="w").grid(row=4, column=0, padx=(12, 4), pady=6, sticky="w")
        self.cp_cat = ctk.CTkComboBox(
            form, values=["custom", "llm", "ai_tool", "search", "dev", "browser", "cloud"],
            font=ctk.CTkFont(size=12), width=150,
        )
        self.cp_cat.grid(row=4, column=1, padx=(4, 12), pady=6, sticky="w")

        self.cp_btn = ctk.CTkButton(
            f, text="✅  Create Provider",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=SUCCESS_COLOR, hover_color=SUCCESS_HOVER,
            height=36, width=200,
            command=self._save_custom_provider,
        )
        self.cp_btn.grid(row=3, column=0, pady=12)

        self.cp_status = ctk.CTkLabel(f, text="", font=ctk.CTkFont(size=12))
        self.cp_status.grid(row=4, column=0, sticky="w")

    # ======================================================================
    # ABOUT TAB
    # ======================================================================

    def _build_about(self):
        f = self.frames["about"]

        ctk.CTkLabel(
            f, text="🔑  Digital Keys",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            f, text="Version 1.0.0",
            font=ctk.CTkFont(size=13),
            text_color=("#666666", "#999999"),
        ).pack(pady=(0, 16))

        info = ctk.CTkFrame(f, corner_radius=8)
        info.pack(fill="x", padx=40, pady=8)

        items = [
            ("🔐", "Encrypted Vault", "Argon2id + AES-256-GCM encryption"),
            ("🔑", "Credential Manager", "Store API keys, passwords, and secrets"),
            ("🛠", "Custom Providers", "Add any service with its own auth config"),
            ("📋", "Clipboard Integration", "One-click copy to clipboard"),
            ("🛡", "Agent Proxy", "AI agents use tokens, never see your keys"),
        ]
        for icon, title, desc in items:
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=6)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=icon, font=ctk.CTkFont(size=20)).grid(row=0, column=0, padx=(0, 8))
            ctk.CTkLabel(row, text=title, font=ctk.CTkFont(size=13, weight="bold"),
                         anchor="w").grid(row=0, column=1, sticky="w")
            ctk.CTkLabel(row, text=desc, font=ctk.CTkFont(size=11),
                         text_color=("#666666", "#999999"),
                         anchor="w").grid(row=1, column=1, sticky="w")

        ctk.CTkLabel(
            f, text="\nBuilt by Highline Digital\nMIT License",
            font=ctk.CTkFont(size=12),
            text_color=("#666666", "#999999"),
        ).pack(pady=16)

    # ======================================================================
    # DATA LOADING
    # ======================================================================

    def _initial_load(self):
        self._refresh_all()

    def _refresh_all(self):
        self._check_vault()
        self._load_providers()
        self._refresh_credentials()
        self._refresh_stats()

    def _check_vault(self):
        """Check vault status."""
        rc, out, err = _cli("list", input_str=f"{_get_passphrase()}\n", vault_path=self.vault_path)

        if "No vault" in out or "No vault" in err or "Run 'dk init'" in err or "Run 'digital-keys init'" in err:
            self.status_light.configure(text_color="#f85149")
            self.status_text.configure(text="No vault — run 'dk init' in terminal")
            self.stats["vstatus"].configure(text="No Vault")
            return False

        if rc == 0 or "Vault is empty" in out:
            self.status_light.configure(text_color="#3fb950")
            self.status_text.configure(text="Vault ready ✓")
            self.stats["vstatus"].configure(text="Ready ✓")
            return True

        self.status_light.configure(text_color="#d29922")
        self.status_text.configure(text="Needs passphrase")
        self.stats["vstatus"].configure(text="Locked")
        return True

    def _load_providers(self):
        """Load the built-in provider catalog for the dropdown."""
        try:
            from digital_keys import providers as catalog_mod
            catalog = catalog_mod.catalog()
            names = [f"{p.label} ({p.id})" for p in catalog]
            self.provider_combo.configure(values=names)
            if names:
                self.provider_combo.set(names[0])
            self.stats["provs"].configure(text=str(len(catalog)))
        except Exception as e:
            self.provider_combo.configure(values=["Error loading"])

    def _refresh_credentials(self):
        """Refresh the credentials list from the vault."""
        search = self.search_entry.get().strip().lower()

        rc, out, err = _cli("list", input_str=f"{_get_passphrase()}\n", vault_path=self.vault_path)

        # Clear previous content
        for w in self.creds_container.winfo_children():
            w.destroy()

        if rc != 0 and "Vault is empty" not in out:
            ctk.CTkLabel(
                self.creds_container,
                text="Cannot access vault. Run 'dk init' first, or set DIGITAL_KEYS_PASSPHRASE.",
                font=ctk.CTkFont(size=12), anchor="w",
            ).pack(padx=12, pady=12)
            return

        # Parse credentials from CLI output
        lines = out.strip().split("\n")
        creds = []
        for line in lines:
            line = line.strip()
            if not line or "(* favourite" in line or line.startswith("Vault"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                idx = 0
                if parts[0] in ("*", " "):
                    idx = 1
                elif parts[0] == "-":
                    idx = 1
                elif parts[0].startswith("*") or parts[0].startswith("-"):
                    idx = 1
                rec_id = parts[idx] if idx > 0 else parts[0]
                label = parts[idx + 1] if idx + 1 < len(parts) else parts[idx]

                if not search or search in label.lower() or search in rec_id[:8].lower():
                    creds.append((rec_id, label, line))

        if not creds:
            msg = "No credentials found." if not search else f'No results matching "{search}".'
            ctk.CTkLabel(
                self.creds_container, text=msg,
                font=ctk.CTkFont(size=12), anchor="w",
            ).pack(padx=12, pady=12)
            return

        for rec_id, label, full_line in creds:
            card = ctk.CTkFrame(self.creds_container, corner_radius=6)
            card.pack(fill="x", padx=4, pady=2)
            card.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                card, text=full_line[:70],
                font=ctk.CTkFont(size=11), anchor="w",
            ).grid(row=0, column=0, padx=10, pady=4, sticky="w")

            acts = ctk.CTkFrame(card, fg_color="transparent")
            acts.grid(row=0, column=1, padx=4, pady=2)

            ctk.CTkButton(
                acts, text="👁  Show & Copy", font=ctk.CTkFont(size=11),
                fg_color=BUTTON_COLOR, hover_color=BUTTON_HOVER,
                width=90, height=26,
                command=lambda rid=rec_id: self._reveal(rid),
            ).pack(side="left", padx=2)

            ctk.CTkButton(
                acts, text="🗑", font=ctk.CTkFont(size=11),
                fg_color="#555555", hover_color=DANGER_COLOR,
                width=30, height=26,
                command=lambda rid=rec_id: self._delete(rid),
            ).pack(side="left", padx=2)

    def _refresh_stats(self):
        """Update dashboard statistics."""
        rc, out, err = _cli("list", input_str=f"{_get_passphrase()}\n", vault_path=self.vault_path)

        cred_count = 0
        first_cred = ""
        for line in out.split("\n"):
            line = line.strip()
            if not line or "(* favourite" in line or line.startswith("Vault"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                cred_count += 1
                if not first_cred:
                    first_cred = line[:60]

        self.stats["creds"].configure(text=str(cred_count))

        if cred_count > 0:
            self.recent_label.configure(text=f"  {first_cred}  (+ {cred_count - 1} more)" if cred_count > 1 else f"  {first_cred}")
        else:
            self.recent_label.configure(text="  No credentials yet. Click 'Add Credential' to get started.")

        # Categories count from vault providers
        try:
            from digital_keys import providers as catalog_mod
            cats = set(p.category.value for p in catalog_mod.catalog())
            self.stats["cats"].configure(text=str(len(cats)))
        except Exception:
            pass

    # ======================================================================
    # ACTIONS
    # ======================================================================

    def _reveal(self, rec_id: str):
        """Reveal and copy a credential."""
        pw = _get_passphrase()
        if not pw:
            dialog = ctk.CTkInputDialog(
                text=f"Enter vault passphrase to reveal {rec_id[:8]}:",
                title="Vault Passphrase Required",
            )
            pw = dialog.get_input() or ""

        if not pw:
            return

        rc, out, err = _cli("show", rec_id, "--reveal", input_str=f"{pw}\n", vault_path=self.vault_path)

        if rc != 0:
            self._status(f"❌ {err.strip() or 'Wrong passphrase'}")
            return

        secret = ""
        for line in out.split("\n"):
            if line.startswith("secret"):
                _, _, val = line.partition(":")
                secret = val.strip()
                break

        if secret:
            # Show popup
            win = ctk.CTkToplevel(self)
            win.title(f"Secret: {rec_id[:8]}")
            win.geometry("520x180")
            win.attributes("-topmost", True)
            win.focus_force()

            ctk.CTkLabel(
                win, text="✅  Copied to clipboard!",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#3fb950",
            ).pack(padx=16, pady=(12, 4))

            ctk.CTkLabel(
                win, text="Secret value:",
                font=ctk.CTkFont(size=12),
                anchor="w",
            ).pack(padx=16, anchor="w")

            textbox = ctk.CTkTextbox(win, height=50, font=ctk.CTkFont(size=13, family="monospace"))
            textbox.pack(fill="x", padx=16, pady=4)
            textbox.insert("0.0", secret)
            textbox.configure(state="disabled")

            win.clipboard_clear()
            win.clipboard_append(secret)

            ctk.CTkButton(win, text="Close", command=win.destroy).pack(pady=6)
            self._status(f"✅ Copied {rec_id[:8]} to clipboard")
        else:
            self._status("❌ Could not extract secret")

    def _delete(self, rec_id: str):
        """Delete a credential after confirmation."""
        pw = _get_passphrase()
        if not pw:
            dialog = ctk.CTkInputDialog(
                text=f"Enter passphrase to delete {rec_id[:8]}:",
                title="Confirm Deletion",
            )
            pw = dialog.get_input() or ""

        if not pw:
            return

        rc, out, err = _cli("delete", rec_id, input_str=f"{pw}\n", vault_path=self.vault_path)

        if rc == 0:
            self._status(f"🗑 Deleted {rec_id[:8]}")
            self._refresh_credentials()
            self._refresh_stats()
        else:
            self._status(f"❌ {err.strip() or 'Delete failed'}")

    def _save_credential(self):
        """Save a new credential to the vault."""
        mode = self.add_mode.get()

        if mode == "preset":
            provider_full = self.provider_combo.get()
            provider = provider_full.split("(")[-1].rstrip(")") if "(" in provider_full else provider_full
        else:
            provider = self.provider_entry.get()

        label = self.label_entry.get()
        secret = self.secret_entry.get()

        if not provider:
            self.save_status.configure(text="❌ Please select or enter a provider", text_color="#f85149")
            return
        if not label:
            self.save_status.configure(text="❌ Please enter a label", text_color="#f85149")
            return
        if not secret:
            self.save_status.configure(text="❌ Please enter a secret", text_color="#f85149")
            return

        pw = _get_passphrase()
        if not pw:
            self.save_status.configure(text="❌ Set DIGITAL_KEYS_PASSPHRASE env var or init vault first", text_color="#f85149")
            return

        cmd = [
            "add", "--label", label, "--provider", provider,
            "--kind", self.kind_combo.get(),
            "--category", self.cat_combo.get(),
            "--secret", secret,
        ]

        rc, out, err = _cli(*cmd, input_str=f"{pw}\n", vault_path=self.vault_path)

        if rc == 0:
            self.save_status.configure(text="✅ Credential saved!", text_color="#3fb950")
            self.label_entry.delete(0, "end")
            self.secret_entry.delete(0, "end")
            self._refresh_credentials()
            self._refresh_stats()
        else:
            self.save_status.configure(text=f"❌ {err.strip() or 'Failed'}", text_color="#f85149")

    def _save_custom_provider(self):
        """Create a custom provider in the vault."""
        pid = self.cp["cp_id"].get().strip().lower().replace(" ", "-")
        name = self.cp["cp_name"].get().strip()
        url = self.cp["cp_url"].get().strip()

        if not pid or not name or not url:
            self.cp_status.configure(text="❌ Provider ID, Name, and URL required", text_color="#f85149")
            return

        pw = _get_passphrase()
        if not pw:
            self.cp_status.configure(text="❌ Set DIGITAL_KEYS_PASSPHRASE env var first", text_color="#f85149")
            return

        # Add a placeholder credential to seed the provider in the vault
        cmd = [
            "add", "--label", f"{name} (placeholder)", "--provider", pid,
            "--kind", "api_key", "--category", self.cp_cat.get(),
            "--secret", "replace-me",
        ]
        rc, out, err = _cli(*cmd, input_str=f"{pw}\n", vault_path=self.vault_path)

        if rc == 0:
            self.cp_status.configure(
                text=f"✅ Provider '{name}' created! Now go to the Add tab to store your real key.",
                text_color="#3fb950",
            )
            for key in ("cp_id", "cp_name", "cp_url"):
                self.cp[key].delete(0, "end")
            self._load_providers()
        else:
            self.cp_status.configure(text=f"❌ {err.strip() or 'Failed'}", text_color="#f85149")

    # ======================================================================
    # UTILITIES
    # ======================================================================

    def _status(self, msg: str):
        """Set status bar message."""
        self.statusbar.configure(text=msg)
        self.after(5000, lambda: self.statusbar.configure(text="Ready"))


# ======================================================================
# Entry point
# ======================================================================


def run_gui():
    """Launch the native desktop GUI."""
    app = DigitalKeysApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()