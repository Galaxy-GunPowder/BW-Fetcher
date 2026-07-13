"""Data models for bot-detection recon reports."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


LAYER_NAMES = {
    1: "transport_block",
    2: "http_status_block",
    3: "waf_headers_cookies",
    4: "interstitial",
    5: "immediate_probe",
    6: "listener_beacon",
    7: "honeypot",
    8: "captcha_human_gate",
}


@dataclass
class LayerFinding:
    layer: int
    name: str
    detected: bool
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BotDetectionReport:
    target: str
    final_url: str
    fetch_ok: bool
    http_status: int
    bot_detection_present: bool
    overall_confidence: float
    vendor: Optional[str] = None
    handcraft: bool = False
    layers: List[LayerFinding] = field(default_factory=list)
    trigger_styles: List[str] = field(default_factory=list)
    signal_set: Dict[str, bool] = field(default_factory=dict)
    # All <script src> URLs seen in the HTML (not downloaded).
    challenge_scripts: List[str] = field(default_factory=list)
    script_srcs_in_html: List[str] = field(default_factory=list)
    # Challenge-looking URLs actually fetched via BW_Fetcher (url -> bytes).
    fetched_scripts: Dict[str, int] = field(default_factory=dict)
    # inline_only | external_urls_in_html | fetched_external | dynamic_or_none | ...
    script_delivery: str = "unknown"
    recommended_strategy: str = "direct_fetch"
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    body_bytes: int = 0
    ttfb_ms: int = 0
    profile: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["layers"] = [layer.to_dict() for layer in self.layers]
        return d

    def active_layers(self) -> List[LayerFinding]:
        return [layer for layer in self.layers if layer.detected]
