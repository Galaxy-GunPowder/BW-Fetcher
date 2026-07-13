"""Unified ``bw-fetcher-py`` CLI — fetch HTML and/or bot-detection report."""
from __future__ import annotations

import argparse
import json
import sys

from . import FetchError, fetch, list_profiles
from .probe import analyze_html_file, probe


def build_parser(prog: str = "bw-fetcher-py") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Fetch with BW-Fetcher (C++ TLS fingerprint). "
            "Default: write HTML. Use --report for bot-detection JSON."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  bw-fetcher-py https://example.com -o page.html\n"
            "  bw-fetcher-py https://example.com --report\n"
            "  bw-fetcher-py https://example.com --report --fetch-subresources -o report.json\n"
        ),
    )
    parser.add_argument("url", nargs="?", help="target https URL")
    parser.add_argument(
        "--report",
        action="store_true",
        help="run bot-detection analysis; write JSON (stdout or -o) instead of HTML",
    )
    parser.add_argument(
        "--fetch-scripts",
        action="store_true",
        help="with --report: also download challenge-looking <script src> URLs (same H2 connection)",
    )
    parser.add_argument(
        "--fetch-subresources",
        action="store_true",
        help="with --report: stream-scan HTML and GET each <script src> as discovered",
    )
    parser.add_argument("--max-scripts", type=int, default=5,
                        help="cap for --fetch-scripts (default: 5)")
    parser.add_argument("--max-subresources", type=int, default=32,
                        help="cap for --fetch-subresources (default: 32)")
    parser.add_argument("--html", help="with --report: analyze local HTML instead of fetching")
    parser.add_argument("--status", type=int, default=200,
                        help="HTTP status when using --html (default: 200)")
    parser.add_argument("--profile", default="Chrome143", help="browser TLS profile")
    parser.add_argument("-o", "--out", help="output file (HTML by default, JSON with --report)")
    parser.add_argument("--proxy", help="SOCKS5 proxy host:port")
    parser.add_argument("--proxy-user")
    parser.add_argument("--proxy-pass")
    parser.add_argument("--max-redirects", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--exe", help="path to BW-Fetcher binary")
    parser.add_argument("--list-profiles", action="store_true", help="list profiles and exit")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_profiles:
        for name in list_profiles(exe=args.exe):
            print(name)
        return 0

    if args.fetch_scripts and not args.report:
        parser.error("--fetch-scripts requires --report")
    if args.fetch_subresources and not args.report:
        parser.error("--fetch-subresources requires --report")
    if args.fetch_subresources and args.fetch_scripts:
        parser.error("use --fetch-subresources or --fetch-scripts, not both")

    if args.report:
        return _run_report(args, parser)
    return _run_fetch(args, parser)


def _run_fetch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.html:
        parser.error("--html requires --report")
    if not args.url:
        parser.error("a URL is required (or use --list-profiles)")

    try:
        result = fetch(
            args.url,
            profile=args.profile,
            proxy=args.proxy,
            proxy_user=args.proxy_user,
            proxy_pass=args.proxy_pass,
            max_redirects=args.max_redirects,
            timeout=args.timeout,
            exe=args.exe,
        )
    except (FetchError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(
        f"[bw-fetcher-py] {result.status} {result.url} "
        f"({len(result.body)} bytes, {result.ttfb_ms}ms, {result.profile})",
        file=sys.stderr,
    )

    if args.out:
        with open(args.out, "wb") as f:
            f.write(result.body)
    else:
        sys.stdout.buffer.write(result.body)
        sys.stdout.buffer.flush()

    return 0 if result.ok else 1


def _run_report(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.html:
        report = analyze_html_file(
            args.html, target_url=args.url or "", status=args.status,
        )
    elif args.url:
        try:
            report = probe(
                args.url,
                profile=args.profile,
                proxy=args.proxy,
                proxy_user=args.proxy_user,
                proxy_pass=args.proxy_pass,
                max_redirects=args.max_redirects,
                timeout=args.timeout,
                exe=args.exe,
                fetch_challenge_scripts=args.fetch_scripts,
                max_challenge_scripts=args.max_scripts,
                fetch_subresources=args.fetch_subresources,
                max_subresources=args.max_subresources,
            )
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    else:
        parser.error("provide a URL or --html with --report")

    payload = json.dumps(report.to_dict(), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
            f.write("\n")
    else:
        print(payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
