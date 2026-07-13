"""8-layer bot-detection analyzer (pure Python — no network I/O)."""
from __future__ import annotations

import re
from typing import Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .models import BotDetectionReport, LayerFinding, LAYER_NAMES
from .script_urls import (
    classify_script_delivery,
    extract_script_srcs,
    filter_challenge_script_urls,
)
from .signatures import (
    CAPTCHA_PATTERNS,
    DEFERRED_JS_PATTERNS,
    HONEYPOT_PATTERNS,
    IMMEDIATE_JS_PATTERNS,
    INTERSTITIAL_PATTERNS,
    INTERSTITIAL_SHORT_BODY,
    INLINE_SCRIPT_RE,
    LISTENER_JS_PATTERNS,
    SIGNAL_JS_PATTERNS,
    VENDORS,
)

BodyInput = Union[str, bytes, None]
ExternalScript = Tuple[str, bytes]  # (url, content)


def _body_text(body: BodyInput) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return body


def _lower_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _header_get(headers: Mapping[str, str], name: str) -> str:
    want = name.lower()
    for k, v in headers.items():
        if k.lower() == want:
            return v
    return ""


def _header_blob(headers: Mapping[str, str]) -> str:
    parts = []
    for k, v in headers.items():
        parts.append(f"{k.lower()}:{v.lower()}")
    return "\n".join(parts)


def _regex_any(patterns, text: str) -> List[str]:
    hits = []
    for pat in patterns:
        if pat.search(text):
            hits.append(pat.pattern)
    return hits


def _extract_inline_scripts(body: str) -> Tuple[str, int]:
    parts: List[str] = []
    count = 0
    for m in INLINE_SCRIPT_RE.finditer(body):
        parts.append(m.group(1))
        count += 1
    return "\n".join(parts), count


def _scan_js(js: str) -> Tuple[Dict[str, bool], List[str]]:
    signals = {key: any(p.search(js) for p in pats) for key, pats in SIGNAL_JS_PATTERNS.items()}
    signals = {k: v for k, v in signals.items() if v}

    triggers: List[str] = []
    if any(p.search(js) for p in IMMEDIATE_JS_PATTERNS):
        triggers.append("immediate")
    if any(p.search(js) for p in LISTENER_JS_PATTERNS):
        triggers.append("listener")
    if any(p.search(js) for p in DEFERRED_JS_PATTERNS):
        triggers.append("deferred_probe")
    return signals, triggers


def _match_vendors(
    body: str,
    headers: Mapping[str, str],
    header_blob: str,
    script_blob: str,
) -> Tuple[Optional[str], bool, List[str]]:
    best_vendor: Optional[str] = None
    best_handcraft = False
    best_hits: List[str] = []
    best_score = 0

    headers_l = _lower_headers(headers)

    for vendor in VENDORS:
        hits: List[str] = []
        for key in vendor.headers:
            if key.lower() in headers_l:
                hits.append(f"header:{key}")
        for prefix in vendor.header_prefixes:
            if any(k.startswith(prefix.lower()) for k in headers_l):
                hits.append(f"header_prefix:{prefix}")
        for key, values in vendor.header_values.items():
            got = _header_get(headers, key).lower()
            if any(v in got for v in values):
                hits.append(f"header_value:{key}")
        for cookie in vendor.cookies:
            if cookie.lower() in header_blob:
                hits.append(f"cookie:{cookie}")
        for pat in vendor.body_patterns:
            if re.search(pat, body, re.IGNORECASE):
                hits.append(f"body:{pat}")
        for pat in vendor.script_patterns:
            if re.search(pat, script_blob, re.IGNORECASE) or re.search(pat, body, re.IGNORECASE):
                hits.append(f"script:{pat}")

        if len(hits) > best_score:
            best_score = len(hits)
            best_vendor = vendor.name
            best_handcraft = vendor.handcraft
            best_hits = hits

    return best_vendor, best_handcraft, best_hits


def _layer(n: int) -> LayerFinding:
    return LayerFinding(layer=n, name=LAYER_NAMES[n], detected=False, confidence=0.0)


def analyze(
    target_url: str,
    *,
    status: int = 0,
    headers: Optional[Mapping[str, str]] = None,
    body: BodyInput = None,
    fetch_ok: bool = True,
    fetch_error: Optional[str] = None,
    final_url: Optional[str] = None,
    ttfb_ms: int = 0,
    profile: str = "",
    external_script_bodies: Optional[Sequence[ExternalScript]] = None,
    fetched_scripts: Optional[Mapping[str, int]] = None,
) -> BotDetectionReport:
    """Classify bot-detection from HTML + headers + optional fetched script bodies."""
    headers = dict(headers or {})
    text = _body_text(body)
    header_blob = _header_blob(headers)
    page_url = final_url or target_url

    script_srcs = extract_script_srcs(text)
    challenge_urls = filter_challenge_script_urls(script_srcs, page_url)
    inline_blob, inline_count = _extract_inline_scripts(text)

    # Scan blob: inline JS + external URL strings + downloaded script file contents.
    script_blob_parts = [inline_blob]
    script_blob_parts.extend(script_srcs)
    if external_script_bodies:
        for _url, content in external_script_bodies:
            script_blob_parts.append(_body_text(content))
    script_blob = "\n".join(p for p in script_blob_parts if p)

    report = BotDetectionReport(
        target=target_url,
        final_url=page_url,
        fetch_ok=fetch_ok,
        http_status=status,
        bot_detection_present=False,
        overall_confidence=0.0,
        script_srcs_in_html=script_srcs,
        challenge_scripts=challenge_urls,
        fetched_scripts=dict(fetched_scripts or {}),
        script_delivery=classify_script_delivery(
            inline_count,
            script_srcs,
            challenge_urls,
            len(fetched_scripts or {}),
        ),
        body_bytes=len(text.encode("utf-8", errors="replace")) if text else 0,
        ttfb_ms=ttfb_ms,
        profile=profile,
        error=fetch_error,
    )

    # L1 — transport
    l1 = _layer(1)
    if not fetch_ok:
        l1.detected = True
        l1.confidence = 0.95
        l1.evidence.append(f"fetch_failed:{fetch_error or 'unknown'}")
        report.notes.append("No HTTP body — block may be at TCP/TLS or proxy layer.")
    report.layers.append(l1)

    # L2 — HTTP status block
    l2 = _layer(2)
    if fetch_ok and status in (401, 403, 429, 503):
        l2.detected = True
        l2.confidence = 0.75
        l2.evidence.append(f"status:{status}")
        retry = _header_get(headers, "retry-after")
        if retry:
            l2.evidence.append(f"retry-after:{retry}")
    report.layers.append(l2)

    # L3 — WAF headers / cookies
    l3 = _layer(3)
    vendor, handcraft, vendor_hits = _match_vendors(text, headers, header_blob, script_blob)
    if vendor_hits:
        l3.detected = True
        l3.confidence = min(0.99, 0.55 + 0.08 * len(vendor_hits))
        l3.evidence.extend(vendor_hits)
        report.vendor = vendor
        report.handcraft = handcraft
    report.layers.append(l3)

    if report.script_delivery == "dynamic_or_none" and l3.detected and not challenge_urls:
        report.notes.append(
            "WAF/CDN detected on headers but no challenge <script src> in HTML — "
            "sensor JS may load dynamically after page parse (needs browser or --fetch-scripts)."
        )

    # L4 — interstitial
    l4 = _layer(4)
    inter_hits = _regex_any(INTERSTITIAL_PATTERNS, text)
    if inter_hits:
        l4.detected = True
        l4.evidence.extend(f"text:{h}" for h in inter_hits)
        l4.confidence = 0.88 if len(text) < INTERSTITIAL_SHORT_BODY else 0.72
        if len(text) < INTERSTITIAL_SHORT_BODY:
            l4.evidence.append(f"short_body:{len(text)}")
    report.layers.append(l4)

    # L5 / L6 — JS probes
    l5 = _layer(5)
    l6 = _layer(6)
    if script_blob:
        report.signal_set, js_triggers = _scan_js(script_blob)
        report.trigger_styles.extend(js_triggers)
        if "immediate" in js_triggers:
            l5.detected = True
            l5.confidence = 0.82
            l5.evidence.append("immediate_js_pattern")
        if "listener" in js_triggers:
            l6.detected = True
            l6.confidence = 0.78
            l6.evidence.append("listener_js_pattern")
        if "deferred_probe" in js_triggers:
            report.notes.append("Deferred probe timing detected in page scripts.")
    report.layers.extend([l5, l6])

    # L7 — honeypot
    l7 = _layer(7)
    hp_hits = _regex_any(HONEYPOT_PATTERNS, text)
    if hp_hits:
        l7.detected = True
        l7.confidence = 0.65
        l7.evidence.extend(f"html:{h}" for h in hp_hits)
        if "honeypot" not in report.trigger_styles:
            report.trigger_styles.append("honeypot")
    report.layers.append(l7)

    # L8 — captcha
    l8 = _layer(8)
    cap_hits = _regex_any(CAPTCHA_PATTERNS, text)
    if cap_hits:
        l8.detected = True
        l8.confidence = 0.90
        l8.evidence.extend(f"captcha:{h}" for h in cap_hits)
    report.layers.append(l8)

    active = [l for l in report.layers if l.detected]
    report.bot_detection_present = bool(active)
    report.overall_confidence = max((l.confidence for l in active), default=0.0)

    if not report.vendor and l4.detected and (l5.detected or challenge_urls):
        report.vendor = "handcraft_unknown"
        report.handcraft = True
        report.notes.append(
            "Challenge page with probe scripts but no known enterprise vendor signature."
        )

    if l2.detected and l3.detected and not l4.detected and not l5.detected:
        report.notes.append(
            "Hard edge block: WAF/CDN rejected the request before any challenge page or "
            "probe JS was served (common for CloudFront/AWS WAF geo or IP rules)."
        )

    if l1.detected:
        report.recommended_strategy = "check_network_tls_or_proxy"
    elif l8.detected:
        report.recommended_strategy = "human_captcha_or_turnstile_solver"
    elif l4.detected or l5.detected:
        report.recommended_strategy = "browser_with_js_execution"
    elif l6.detected:
        report.recommended_strategy = "headless_with_behavior_simulation"
    elif l2.detected:
        report.recommended_strategy = "rotate_egress_ip_or_browser_profile"
    elif l3.detected and 200 <= status < 300:
        report.recommended_strategy = "monitor_waf_cookies_may_escalate_on_next_request"
    elif l7.detected:
        report.recommended_strategy = "avoid_honeypot_paths_and_hidden_fields"
    else:
        report.recommended_strategy = "direct_fetch"

    return report
