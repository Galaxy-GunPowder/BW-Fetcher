#!/usr/bin/env python3
"""Run or report BW_Fetcher HTML fetch benchmarks.

Examples
--------
    # Full suite (build BW_Fetcher.exe first)
    python benchmarks/run.py

    # Quick smoke run
    python benchmarks/run.py --runs 1 --warmup 0 --clients bw_fetcher_py,curl

    # Re-print a saved report
    python benchmarks/run.py report benchmarks/results/latest.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH_ROOT))

from bench.clients import list_client_info  # noqa: E402
from bench.models import BenchmarkSuite  # noqa: E402
from bench.report import format_report  # noqa: E402
from bench.runner import run_benchmark  # noqa: E402

DEFAULT_URLS = BENCH_ROOT / "urls.json"
RESULTS_DIR = BENCH_ROOT / "results"


def cmd_run(args: argparse.Namespace) -> int:
    urls_path = Path(args.urls)
    if not urls_path.is_file():
        print(f"URLs file not found: {urls_path}", file=sys.stderr)
        return 2

    client_names = [c.strip() for c in args.clients.split(",") if c.strip()] if args.clients else None

    suite = run_benchmark(
        urls_path,
        client_names=client_names,
        runs=args.runs,
        warmup=args.warmup,
        timeout=args.timeout,
        profile=args.profile,
        bw_fetcher_exe=args.exe,
    )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = RESULTS_DIR / f"{stamp}.json"
    suite.save(out_path)

    latest = RESULTS_DIR / "latest.json"
    latest.write_text(out_path.read_text(encoding="utf-8"), encoding="utf-8")

    report = format_report(suite)
    print()
    print(report)

    if args.save_report:
        report_path = RESULTS_DIR / f"{stamp}.txt"
        report_path.write_text(report, encoding="utf-8")
        print(f"Report saved: {report_path}")

    print(f"Results saved: {out_path}")
    print(f"Latest copy:   {latest}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.result_file)
    if not path.is_file():
        print(f"Result file not found: {path}", file=sys.stderr)
        return 2
    suite = BenchmarkSuite.load(path)
    print(format_report(suite))
    return 0


def cmd_list_clients(_: argparse.Namespace) -> int:
    for row in list_client_info():
        status = "yes" if row["available"] else "no"
        print(f"{row['name']:<12} available={status}  {row['description']}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    a = BenchmarkSuite.load(Path(args.left))
    b = BenchmarkSuite.load(Path(args.right))
    from bench.report import aggregate, bw_fetcher_vs_others

    stats_a = { (s.client, s.url_name): s for s in aggregate(a) }
    stats_b = { (s.client, s.url_name): s for s in aggregate(b) }

    print(f"Left:  {args.left} ({a.created_at})")
    print(f"Right: {args.right} ({b.created_at})")
    print("-" * 60)
    keys = sorted(set(stats_a) | set(stats_b))
    for key in keys:
        sa, sb = stats_a.get(key), stats_b.get(key)
        if not sa or not sb:
            continue
        delta = sb.median_total_ms - sa.median_total_ms
        sign = "+" if delta > 0 else ""
        print(
            f"{key[0]:<12} {key[1]:<16} "
            f"{sa.median_total_ms:>8.0f}ms -> {sb.median_total_ms:>8.0f}ms  ({sign}{delta:.0f}ms)"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command")

    run = sub.add_parser("run", help="Run benchmark suite (default)")
    run.add_argument("--urls", default=str(DEFAULT_URLS), help="JSON file listing target pages")
    run.add_argument("--clients", default="", help="Comma-separated subset (default: all available)")
    run.add_argument("--runs", type=int, default=3, help="Measured runs per URL/client")
    run.add_argument("--warmup", type=int, default=1, help="Warmup runs discarded from stats")
    run.add_argument("--timeout", type=float, default=60.0, help="Per-fetch timeout seconds")
    run.add_argument("--profile", default="Chrome143", help="BW_Fetcher TLS profile")
    run.add_argument("--exe", default=None, help="Path to BW_Fetcher.exe")
    run.add_argument("--save-report", action="store_true", help="Also write text report beside JSON")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", help="Print report from saved JSON")
    rep.add_argument("result_file", help="Path to a results/*.json file")
    rep.set_defaults(func=cmd_report)

    lst = sub.add_parser("list-clients", help="Show registered clients and availability")
    lst.set_defaults(func=cmd_list_clients)

    cmp = sub.add_parser("compare", help="Compare median times between two result files")
    cmp.add_argument("left", help="Baseline results JSON")
    cmp.add_argument("right", help="New results JSON")
    cmp.set_defaults(func=cmd_compare)

    # Default subcommand: run
    p.set_defaults(func=cmd_run, command="run")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Allow `python run.py report file.json` without explicit subcommand
    if argv and argv[0] == "report":
        return cmd_report(argparse.Namespace(result_file=argv[1] if len(argv) > 1 else str(RESULTS_DIR / "latest.json")))
    if argv and argv[0] == "list-clients":
        return cmd_list_clients(argparse.Namespace())

    parser = build_parser()
    if not argv:
        args = parser.parse_args(["run"])
    elif argv[0] not in ("run", "report", "list-clients", "compare"):
        args = parser.parse_args(["run"] + argv)
    else:
        args = parser.parse_args(argv)

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
