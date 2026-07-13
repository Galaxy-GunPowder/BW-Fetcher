"""Summarize stored benchmark JSON results."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import median
from typing import Dict, List, Optional, Tuple

from .models import BenchmarkSuite, FetchTiming


@dataclass
class ClientUrlStats:
    client: str
    url_name: str
    samples: int
    success_rate: float
    median_total_ms: float
    median_ttfb_ms: Optional[float]
    median_kbps: float
    median_bytes: int


def _measure_rows(timings: List[FetchTiming], include_warmup: bool = False) -> List[FetchTiming]:
    if include_warmup:
        return timings
    return [t for t in timings if not t.is_warmup and t.ok]


def aggregate(suite: BenchmarkSuite) -> List[ClientUrlStats]:
    buckets: Dict[Tuple[str, str], List[FetchTiming]] = defaultdict(list)
    for t in _measure_rows(suite.timings):
        buckets[(t.client, t.url_name)].append(t)

    stats: List[ClientUrlStats] = []
    for (client, url_name), rows in sorted(buckets.items()):
        ok_rows = [r for r in rows if r.ok]
        all_rows = rows  # already filtered to non-warmup ok in _measure_rows mostly
        samples = len(ok_rows)
        success = len(ok_rows) / len(all_rows) if all_rows else 0.0
        if not ok_rows:
            stats.append(
                ClientUrlStats(
                    client=client,
                    url_name=url_name,
                    samples=0,
                    success_rate=success,
                    median_total_ms=0.0,
                    median_ttfb_ms=None,
                    median_kbps=0.0,
                    median_bytes=0,
                )
            )
            continue

        totals = sorted(r.total_ms for r in ok_rows)
        ttfbs = sorted(r.ttfb_ms for r in ok_rows if r.ttfb_ms is not None)
        kbps = sorted(r.throughput_kbps for r in ok_rows)
        bytes_ = sorted(r.bytes_received for r in ok_rows)

        stats.append(
            ClientUrlStats(
                client=client,
                url_name=url_name,
                samples=samples,
                success_rate=success,
                median_total_ms=median(totals),
                median_ttfb_ms=median(ttfbs) if ttfbs else None,
                median_kbps=median(kbps),
                median_bytes=int(median(bytes_)),
            )
        )
    return stats


def winners_by_url(stats: List[ClientUrlStats]) -> Dict[str, str]:
    """Return fastest client per URL by median total time."""
    by_url: Dict[str, List[ClientUrlStats]] = defaultdict(list)
    for s in stats:
        if s.samples > 0:
            by_url[s.url_name].append(s)

    result = {}
    for url_name, rows in by_url.items():
        best = min(rows, key=lambda r: r.median_total_ms)
        result[url_name] = best.client
    return result


def bw_fetcher_vs_others(stats: List[ClientUrlStats]) -> List[dict]:
    """Per-URL speedup of bw_fetcher median total time vs each other client."""
    by_url: Dict[str, Dict[str, ClientUrlStats]] = defaultdict(dict)
    for s in stats:
        by_url[s.url_name][s.client] = s

    rows = []
    for url_name, clients in sorted(by_url.items()):
        bw = clients.get("bw_fetcher_py")
        if not bw or bw.samples == 0:
            continue
        for name, other in sorted(clients.items()):
            if name == "bw_fetcher_py" or other.samples == 0:
                continue
            ratio = other.median_total_ms / bw.median_total_ms
            rows.append(
                {
                    "url": url_name,
                    "vs": name,
                    "bw_fetcher_ms": round(bw.median_total_ms, 1),
                    "other_ms": round(other.median_total_ms, 1),
                    "faster": "bw_fetcher_py" if ratio > 1.0 else name,
                    "ratio": round(ratio, 2),
                }
            )
    return rows


def format_report(suite: BenchmarkSuite) -> str:
    stats = aggregate(suite)
    winners = winners_by_url(stats)
    comparisons = bw_fetcher_vs_others(stats)

    lines = [
        "=" * 72,
        "BW_Fetcher HTML fetch benchmark",
        f"Run: {suite.created_at}",
        f"Host: {suite.hostname}",
        f"Clients: {', '.join(suite.clients)}",
        "=" * 72,
        "",
        "Median total time (ms) per URL - lower is better",
        "-" * 72,
    ]

    clients = sorted({s.client for s in stats})
    urls = sorted({s.url_name for s in stats})

    header = f"{'URL':<18}" + "".join(f"{c:>14}" for c in clients)
    lines.append(header)
    lines.append("-" * len(header))

    lookup = {(s.client, s.url_name): s for s in stats}
    for url in urls:
        row = f"{url:<18}"
        for client in clients:
            s = lookup.get((client, url))
            if s and s.samples:
                cell = f"{s.median_total_ms:>12.0f}ms"
                if winners.get(url) == client:
                    cell += "*"
            else:
                cell = f"{'n/a':>14}"
            row += f"{cell:>14}"
        lines.append(row)

    lines.extend(["", "(* = fastest for that URL)", ""])

    if comparisons:
        lines.append("BW_Fetcher vs others (median total ms, ratio > 1 means bw_fetcher is faster)")
        lines.append("-" * 72)
        for c in comparisons:
            faster = c["faster"]
            lines.append(
                f"  {c['url']:<18} vs {c['vs']:<10} "
                f"bw={c['bw_fetcher_ms']:>7.0f}ms  other={c['other_ms']:>7.0f}ms  "
                f"winner={faster}  ratio={c['ratio']:.2f}x"
            )
        lines.append("")

    # Overall scorecard
    bw_wins = sum(1 for u, w in winners.items() if w == "bw_fetcher_py")
    lines.append(f"BW_Fetcher fastest on {bw_wins}/{len(winners)} URLs")
    lines.append("=" * 72)
    return "\n".join(lines)
