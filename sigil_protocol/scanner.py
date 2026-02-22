"""
Core scanner — fetches the SIGIL pattern bundle from the public registry
and scans arbitrary text/JSON for security findings.

Uses no EUPL code — this file is MIT-licensed and calls the registry HTTP API.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

REGISTRY_URL = os.getenv(
    "SIGIL_REGISTRY_URL", "https://registry.sigil-protocol.org"
)
BUNDLE_TTL   = int(os.getenv("SIGIL_BUNDLE_TTL", "300"))   # seconds
OFFLINE      = os.getenv("SIGIL_OFFLINE", "").lower() in ("1", "true", "yes")
MIN_SEVERITY = os.getenv("SIGIL_MIN_SEVERITY", "High")     # Warn|High|Critical

# ── Built-in fallback patterns (subset) ──────────────────────────────────────
_BUILTIN_PATTERNS = [
    {"id": "aws_access_key_id",    "severity": "Critical", "regex": r"AKIA[0-9A-Z]{16}"},
    {"id": "openai_api_key",       "severity": "Critical", "regex": r"sk-[a-zA-Z0-9]{32,}"},
    {"id": "github_pat",           "severity": "Critical", "regex": r"gh[ps]_[a-zA-Z0-9]{36}"},
    {"id": "rsa_private_key",      "severity": "Critical", "regex": r"-----BEGIN RSA PRIVATE KEY-----"},
    {"id": "generic_secret",       "severity": "High",     "regex": r"(?i)(secret|password|passwd|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{16,}"},
    {"id": "sql_drop_table",       "severity": "Critical", "regex": r"(?i)DROP\s+TABLE\s+\w+"},
    {"id": "sql_delete_no_where",  "severity": "High",     "regex": r"(?i)DELETE\s+FROM\s+\w+\s*(?!WHERE)"},
    {"id": "sql_truncate",         "severity": "High",     "regex": r"(?i)TRUNCATE\s+(TABLE\s+)?\w+"},
    {"id": "prompt_injection",     "severity": "High",     "regex": r"(?i)(ignore previous instructions|you are now|act as|jailbreak)"},
]


class Severity(str, Enum):
    Warn     = "Warn"
    High     = "High"
    Critical = "Critical"

    @classmethod
    def _order(cls) -> dict[str, int]:
        return {"Warn": 0, "High": 1, "Critical": 2}

    def __ge__(self, other: "Severity") -> bool:
        return self._order()[self.value] >= self._order()[other.value]


@dataclass
class ScanResult:
    hit: bool
    pattern: Optional[str] = None
    severity: Optional[Severity] = None
    category: Optional[str] = None
    all_hits: list[dict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.hit and self.severity == Severity.Critical

    @property
    def warned(self) -> bool:
        return self.hit and self.severity in (Severity.High, Severity.Warn)

    def __bool__(self) -> bool:
        return self.hit


class RemoteScanner:
    """
    Fetches the SIGIL pattern bundle from registry.sigil-protocol.org and
    compiles regexes locally. Patterns are cached for SIGIL_BUNDLE_TTL seconds
    (default 5 minutes). Falls back to built-ins if the registry is unreachable.
    """

    def __init__(self) -> None:
        self._patterns: list[dict] = []
        self._compiled: list[tuple[re.Pattern, dict]] = []
        self._fetched_at: float = 0.0
        self._min_sev = Severity(MIN_SEVERITY)

    def _needs_refresh(self) -> bool:
        return time.monotonic() - self._fetched_at > BUNDLE_TTL

    def _load(self) -> None:
        if OFFLINE:
            self._patterns = _BUILTIN_PATTERNS
        else:
            try:
                resp = httpx.get(
                    f"{REGISTRY_URL}/patterns/bundle",
                    timeout=5.0,
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
                self._patterns = data if isinstance(data, list) else data.get("patterns", [])
            except Exception:
                if not self._patterns:
                    self._patterns = _BUILTIN_PATTERNS

        self._compiled = []
        for p in self._patterns:
            try:
                self._compiled.append((re.compile(p["regex"]), p))
            except re.error:
                pass
        self._fetched_at = time.monotonic()

    def scan(self, text: str) -> ScanResult:
        """Scan text for security findings. Returns the highest-severity hit."""
        if self._needs_refresh():
            self._load()

        if isinstance(text, (dict, list)):
            text = json.dumps(text)

        hits = []
        for pattern, meta in self._compiled:
            if pattern.search(text):
                sev = Severity(meta.get("severity", "Warn"))
                if sev >= self._min_sev:
                    hits.append({**meta, "severity_enum": sev})

        if not hits:
            return ScanResult(hit=False)

        # Return the highest-severity hit as the primary
        hits.sort(key=lambda h: Severity._order()[h["severity_enum"].value], reverse=True)
        top = hits[0]
        return ScanResult(
            hit=True,
            pattern=top.get("id") or top.get("pattern_name"),
            severity=top["severity_enum"],
            category=top.get("category"),
            all_hits=hits,
        )

    def scan_json(self, obj) -> ScanResult:
        return self.scan(json.dumps(obj))


# Module-level default scanner instance (lazy-loaded)
_default_scanner: Optional[RemoteScanner] = None


def scanner() -> RemoteScanner:
    """Return the module-level default scanner, creating it if necessary."""
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = RemoteScanner()
    return _default_scanner


def scan(text: str) -> ScanResult:
    """Convenience function — scan text using the default scanner."""
    return scanner().scan(text)
