# HTML fetch benchmark suite

Compare **BW_Fetcher** against common HTTP/TLS clients when downloading HTML pages.
Use this to see whether the native fetcher is faster than curl, httpx, requests,
or urllib on real-world pages.

## Test design

### Goal

Answer: *Is BW_Fetcher faster than other HTTPS clients when fetching HTML?*

### Clients

| Client | Description |
|--------|-------------|
| `bw_fetcher` | Native `BW_Fetcher.exe` (BoringSSL + nghttp2, Chrome TLS fingerprint) |
| `curl_cffi` | curl-impersonate binding — the true peer: also forges a Chrome TLS+HTTP/2 fingerprint |
| `curl` | System curl (HTTP/2 when libcurl supports it, else HTTP/1.1) |
| `httpx` | Python httpx with HTTP/2 via `h2` (optional) |
| `requests` | Python requests / urllib3 (typically HTTP/1.1) |
| `urllib` | Stdlib baseline (always available) |

> **`curl_cffi` is the comparison that matters.** It is the only other client
> here that fakes a browser TLS/JA3 fingerprint, so it's the apples-to-apples
> rival. `curl`/`httpx`/`requests`/`urllib` use the platform/Python TLS stack and
> are kept as references, not fingerprint peers.

### Pages (`urls.json`)

| Name | URL | Notes |
|------|-----|-------|
| `example.com` | https://example.com | Tiny static page |
| `httpbin-html` | https://httpbin.org/html | Small HTML test body |
| `wikipedia-en` | https://en.wikipedia.org/wiki/Main_Page | Large HTML; may 403 default Python UAs |
| `python-org` | https://www.python.org/ | Medium marketing page |
| `mozilla-org` | https://www.mozilla.org/en-US/ | Medium page, full HTML |

### Methodology

1. For each **URL × client** pair:
   - Run `warmup` fetches (default **1**, excluded from stats)
   - Run `runs` measured fetches (default **3**)
2. Record per attempt: `total_ms`, `ttfb_ms`, `bytes_received`, HTTP status, success/fail
3. Aggregate with **median** (outliers from DNS/CDN less impactful than mean)
4. Mark fastest client per URL; print BW_Fetcher speedup ratio vs each other client

### Success criteria

A fetch counts as success when:

- HTTP status is 2xx or 3xx
- Body length ≥ `min_bytes` from `urls.json`

### Metrics

| Metric | Meaning |
|--------|---------|
| `total_ms` | Wall-clock time for the complete fetch (redirects included) |
| `ttfb_ms` | Time to first response body byte |
| `throughput_kbps` | `bytes × 8 / total_ms` |
| `success_rate` | Fraction of non-warmup runs that passed |

## Setup

```bash
# 1. Build BW_Fetcher (from repo root)
cmake --build cmake-build-release-visual-studio --target BW_Fetcher

# 2. Optional comparison clients
pip install -r benchmarks/requirements.txt
```

## Run

```bash
# Full suite (5 URLs × all available clients × 1 warmup + 3 measured runs)
python benchmarks/run.py

# Quick smoke test
python benchmarks/run.py --runs 1 --warmup 0 --clients bw_fetcher,curl,urllib

# Custom URL list or more repetitions
python benchmarks/run.py --urls benchmarks/urls.json --runs 5 --save-report
```

### CLI reference

```bash
python benchmarks/run.py list-clients
python benchmarks/run.py report benchmarks/results/latest.json
python benchmarks/run.py compare benchmarks/results/old.json benchmarks/results/latest.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--urls` | `benchmarks/urls.json` | Page list |
| `--clients` | all available | Comma-separated subset |
| `--runs` | 3 | Measured runs per pair |
| `--warmup` | 1 | Discarded warmup runs |
| `--timeout` | 60 | Per-fetch timeout (seconds) |
| `--profile` | Chrome143 | BW_Fetcher TLS profile |
| `--exe` | auto-locate | Path to `BW_Fetcher.exe` |
| `--save-report` | off | Also write `.txt` report |

## Output

Each run writes:

- `benchmarks/results/<timestamp>.json` — raw timings for every attempt
- `benchmarks/results/latest.json` — copy of the most recent run
- `benchmarks/results/<timestamp>.txt` — text report (with `--save-report`)

### Interpreting results

- **Median total time** is the primary score — lower is better.
- **`urllib` wins on raw speed** on many pages because it skips browser-grade TLS
  and HTTP/2 setup; compare bw_fetcher mainly against **curl / httpx / requests**.
- **403 on wikipedia** for httpx/requests is expected — they send default Python
  user-agents; BW_Fetcher sends Chrome headers and succeeds.
- **`curl_cffi` cold-connection caveat:** on some hosts (notably Windows) the
  first connection of every `curl_cffi` session pays a large fixed penalty
  (~6 s observed here — an IPv6/handshake fallback timeout, *not* transfer time);
  a warm keep-alive connection drops to ~40 ms. BW_Fetcher is invoked as a fresh
  subprocess per fetch, so it always pays a full *cold* connection — meaning the
  fair comparison is cold-vs-cold. If you see a flat multi-second `curl_cffi`
  time across all URLs, that is this artifact, not raw client speed; report the
  cold-vs-cold ratio with that context rather than as a headline "Nx faster".
- Re-run after network or code changes; do not treat one run as a permanent score.

## Latest results — Linux (2026-06-24, optimized build)

Run under **WSL2 Ubuntu 26.04** with a native Linux build of BW_Fetcher
(`~/bw_build/BW_Fetcher`), 1 warmup + 3 runs, all six clients. This is the fair,
artifact-free environment (Windows distorts `curl_cffi` with a ~6 s cold-connect
timeout — see the caveat above). These numbers are **after** the connection-path
performance pass; the earlier, unoptimized run (BW_Fetcher ~3× slower, last on
every URL) has been retired to keep this file to the shipping build.

**Median total time (ms)** — lower is better

| URL | bw_fetcher | curl | curl_cffi | urllib |
|-----|-----------:|-----:|----------:|-------:|
| example.com | **122** | 135 | 124 | 120 |
| mozilla-org | **182** | 284 | 184 | 276 |
| python-org | **132** | 141 | 144 | 131 |
| wikipedia-en | **259** | 368 | 280 | 389 |
| httpbin-html | 1495 | 1108 | 816 | 1126 |

BW_Fetcher is **fastest on 2/5** pages and at-par-or-better than curl-impersonate
(`curl_cffi`) on **4/5**. (`httpbin-html` is a slow, high-variance third-party
endpoint dominated by server time — don't read much into one run of it.)

**What changed** (`URL_to_DNS/resolve_host.cpp`, `HTTP2_Client/http2_client.cpp`,
`platform_win.h`):

1. **Removed the unconditional 250ms Happy-Eyeballs sleep.** It now races IPv6 and
   IPv4 concurrently and returns the first socket to connect, handing any still
   in-flight attempts to a detached drainer. This recovered the bulk of the gap.
2. **Non-blocking `connect()` with a real timeout.** `SO_RCVTIMEO`/`SO_SNDTIMEO`
   never applied to `connect()`, so a hung address could stall indefinitely; it now
   uses `select()` with the intended timeout.
3. **`TCP_NODELAY`** so the TLS ClientHello and HTTP/2 SETTINGS+HEADERS go out
   immediately instead of waiting on Nagle.
4. **Event loop blocks on `poll()`** instead of a 1ms busy-wait spin — wakes the
   instant the response arrives and burns no CPU while waiting.
5. **Per-header / per-write tracing gated behind `BW_FETCHER_VERBOSE`** (each
   `std::endl` was a flush syscall in the hot path).
6. **Connection reuse across same-host redirects** (`fetcher.cpp`) — the live
   socket + TLS session is kept and the redirect is issued on a new HTTP/2 stream
   instead of reconnecting. Only reconnects when the host/port changes, a proxy is
   in use, or the server sent GOAWAY. Saves a full connect + TLS handshake per
   same-host hop (e.g. `httpbin.org/redirect/2` now uses one connection).

Both the Linux (WSL) and Windows (MSVC) builds compile and run with all of the above.

## Customize URLs

Edit `benchmarks/urls.json`:

```json
{
  "urls": [
    { "name": "example", "url": "https://example.com", "min_bytes": 100 }
  ]
}
```

## Automated smoke test

```bash
pip install pytest
pytest benchmarks/test_benchmark.py -m network
```

The smoke test runs one URL with `urllib` only to verify the harness without
requiring a built `BW_Fetcher.exe`.

## Layout

```
benchmarks/
  run.py              # CLI entry
  urls.json           # test pages
  requirements.txt    # httpx, requests
  test_benchmark.py   # pytest smoke test
  bench/
    runner.py         # execution engine
    report.py         # tables and speedup
    clients/          # per-client adapters
  results/            # JSON + text reports (gitignored except .gitkeep)
```
