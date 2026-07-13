"""Bot-detection recon: fetch via C++ + analyze in Python."""
from __future__ import annotations

from .analyzer import analyze
from .models import BotDetectionReport, LayerFinding, LAYER_NAMES
from .script_urls import (
    classify_script_delivery,
    discover_subresource_urls,
    extract_script_srcs,
    filter_challenge_script_urls,
    IncrementalSubresourceScanner,
    is_challenge_script_url,
    is_fetchable_subresource,
)

__all__ = [
    "analyze",
    "BotDetectionReport",
    "LayerFinding",
    "LAYER_NAMES",
    "extract_script_srcs",
    "filter_challenge_script_urls",
    "is_challenge_script_url",
    "discover_subresource_urls",
    "IncrementalSubresourceScanner",
    "is_fetchable_subresource",
    "classify_script_delivery",
]
