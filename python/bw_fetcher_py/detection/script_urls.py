"""Find and classify <script src> URLs from HTML (challenge vs normal site JS)."""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse

from .signatures import SCRIPT_SRC_RE

LINK_MODULEPRELOAD_RE = re.compile(
    r'<link\b[^>]*\b(?:'
    r'rel\s*=\s*["\'][^"\']*\bmodulepreload\b[^"\']*["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']'
    r'|href\s*=\s*["\']([^"\']+)["\'][^>]*\brel\s*=\s*["\'][^"\']*\bmodulepreload\b[^"\']*["\']'
    r')',
    re.IGNORECASE,
)
LINK_PRELOAD_SCRIPT_RE = re.compile(
    r'<link\b[^>]*\b(?:'
    r'rel\s*=\s*["\'][^"\']*\bpreload\b[^"\']*["\'][^>]*\bas\s*=\s*["\']script["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']'
    r'|href\s*=\s*["\']([^"\']+)["\'][^>]*\brel\s*=\s*["\'][^"\']*\bpreload\b[^"\']*["\'][^>]*\bas\s*=\s*["\']script["\']'
    r')',
    re.IGNORECASE,
)

_NON_FETCHABLE_PREFIXES = (
    "data:", "blob:", "javascript:", "vbscript:", "mailto:", "tel:",
)

# URL path/host fragments typical of bot-detection / sensor scripts (not app bundles).
CHALLENGE_URL_PATTERNS: tuple[str, ...] = (
    r"/cdn-cgi/challenge-platform/",
    r"challenges\.cloudflare\.com",
    r"/akam/",
    r"bmak\.js",
    r"/datadome/",
    r"datadome\.co",
    r"px-cloud\.net",
    r"perimeterx\.net",
    r"/149e9513-",          # kasada
    r"kasada\.io",
    r"/botjs/",
    r"/_Incapsula_Resource",
    r"recaptcha/api",
    r"hcaptcha\.com",
    r"challenges\.cloudflare\.com/turnstile",
    r"/js/[A-Za-z0-9_-]{8,}\.js",  # H1Base one-time token script
)

_CHALLENGE_RE = tuple(re.compile(p, re.IGNORECASE) for p in CHALLENGE_URL_PATTERNS)


def extract_script_srcs(html: str) -> List[str]:
    """Every ``<script src="...">`` value from the HTML (order preserved)."""
    return [m.group(1) for m in SCRIPT_SRC_RE.finditer(html)]


def _link_hrefs(pattern: re.Pattern[str], html: str) -> List[str]:
    out: List[str] = []
    for m in pattern.finditer(html):
        href = m.group(1) or m.group(2) or ""
        if href:
            out.append(href)
    return out


def extract_subresource_candidates(html: str) -> List[str]:
    """Script-related URLs in HTML (not yet resolved to absolute)."""
    out: List[str] = []
    out.extend(extract_script_srcs(html))
    out.extend(_link_hrefs(LINK_MODULEPRELOAD_RE, html))
    out.extend(_link_hrefs(LINK_PRELOAD_SCRIPT_RE, html))
    return out


class IncrementalSubresourceScanner:
    """Scan HTML incrementally as body chunks arrive (mirrors C++ scanner)."""

    _TAIL_GUARD = 2048

    def __init__(self, page_url: str, max_count: int = 32) -> None:
        self.page_url = page_url
        self.max_count = max_count
        self._buffer = ""
        self._scan_cursor = 0
        self._seen_abs: set[str] = set()
        self._found = 0

    def _resolve_new(self, raw: List[str]) -> List[str]:
        out: List[str] = []
        for src in raw:
            if not is_fetchable_subresource(src):
                continue
            abs_url = resolve_script_url(src, self.page_url)
            if abs_url in self._seen_abs:
                continue
            self._seen_abs.add(abs_url)
            out.append(abs_url)
            self._found += 1
            if self.max_count > 0 and self._found >= self.max_count:
                break
        return out

    def _scan_window(self, begin: int, end: int) -> List[str]:
        if begin >= end or end > len(self._buffer):
            return []
        if self.max_count > 0 and self._found >= self.max_count:
            return []
        window = self._buffer[begin:end]
        return self._resolve_new(extract_subresource_candidates(window))

    def feed(self, data: str | bytes) -> List[str]:
        if self.max_count > 0 and self._found >= self.max_count:
            return []
        chunk = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        if not chunk:
            return []
        self._buffer += chunk
        safe_end = len(self._buffer) - self._TAIL_GUARD if len(self._buffer) > self._TAIL_GUARD else 0
        if safe_end <= self._scan_cursor:
            return []
        out = self._scan_window(self._scan_cursor, safe_end)
        self._scan_cursor = safe_end
        return out

    def finalize(self) -> List[str]:
        if self._scan_cursor >= len(self._buffer):
            return []
        return self._scan_window(self._scan_cursor, len(self._buffer))


def is_fetchable_subresource(url: str) -> bool:
    u = url.strip()
    if not u or u.startswith("#"):
        return False
    lower = u.lower()
    return not any(lower.startswith(p) for p in _NON_FETCHABLE_PREFIXES)


def resolve_script_url(src: str, page_url: str) -> str:
    return urljoin(page_url, src.strip())


def is_challenge_script_url(url: str) -> bool:
    return any(p.search(url) for p in _CHALLENGE_RE)


def filter_challenge_script_urls(srcs: List[str], page_url: str) -> List[str]:
    """Absolute URLs that look like bot-detection / sensor scripts."""
    seen: set[str] = set()
    out: List[str] = []
    for src in srcs:
        abs_url = resolve_script_url(src, page_url)
        if abs_url in seen:
            continue
        if is_challenge_script_url(abs_url) or is_challenge_script_url(src):
            seen.add(abs_url)
            out.append(abs_url)
    return out


def discover_subresource_urls(html: str, page_url: str, max_count: int = 32) -> List[str]:
    """Absolute, fetchable script-related URLs from a complete HTML buffer."""
    scanner = IncrementalSubresourceScanner(page_url, max_count)
    out = scanner.feed(html)
    out.extend(scanner.finalize())
    return out


def classify_script_delivery(
    inline_script_count: int,
    script_srcs: List[str],
    challenge_srcs: List[str],
    fetched_count: int,
) -> str:
    """How challenge JS appears to be delivered on the first HTML response."""
    if fetched_count > 0:
        return "fetched_external"
    if challenge_srcs:
        return "external_urls_in_html"
    if inline_script_count > 0 and any(
        k in " ".join(script_srcs).lower()
        for k in ("challenge", "sensor", "botjs", "cdn-cgi")
    ):
        return "inline_bootstrap"
    if inline_script_count > 0:
        return "inline_only"
    if script_srcs:
        return "app_scripts_only"
    return "dynamic_or_none"
