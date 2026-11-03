from __future__ import annotations

import hashlib
import re
from typing import Any

FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")

_ALLOWED_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@+-"
)


def _component(value: object) -> str:
    text = str(value or "").strip().replace("/", "%2f").replace(":", "%3a")
    if not text:
        raise ValueError("Fingerprint component cannot be empty")
    if len(text) > 200:
        text = text[:200]
    text = "".join(char if char in _ALLOWED_CHARS else "%" + format(ord(char), "02x") for char in text)
    return text


def finding_fingerprint(
    project: str,
    file: str,
    vulnerability_class: str,
    function: str | None = None,
    sink: str | None = None,
) -> str:
    """Build a short, stable, source-derived fingerprint for finding deduplication."""
    parts = [
        _component(project),
        _component(file),
        _component(function or "-"),
        _component(sink or "-"),
        _component(vulnerability_class),
    ]
    raw = ":".join(parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"fp/{parts[0]}/{digest}"


def normalize_finding_fingerprint(finding: dict[str, Any]) -> str:
    """Return an explicit fingerprint, or derive a stable one from source identity."""
    explicit = str(finding.get("fingerprint", "")).strip()
    if explicit:
        if not FINGERPRINT_RE.fullmatch(explicit):
            raise ValueError("Invalid fingerprint")
        return explicit
    location = finding.get("location") or {}
    title = str(finding.get("title", "unknown"))
    vuln_class = str(finding.get("cwe") or title[:60])
    return finding_fingerprint(
        str(finding.get("project_id") or "unknown"),
        str(location.get("file") or "unknown"),
        vuln_class,
        str(location.get("function") or ""),
    )
