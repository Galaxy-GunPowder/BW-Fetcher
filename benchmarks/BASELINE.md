# Benchmark baseline — 2026-06-24 (optimized build)

Frozen snapshot of the **optimized** BW_Fetcher (after the connection-path
performance pass). This is the number to beat on future runs. Refresh locally with:

```bash
python benchmarks/run.py --save-report
```

## Configuration

| Setting | Value |
|---------|-------|
| Date | 2026-06-24 |
| Environment | WSL2 Ubuntu 26.04, native Linux build |
| Profile | Chrome143 |
| Warmup runs | 1 |
| Measured runs | 3 |
| Clients | bw_fetcher, curl, curl_cffi, httpx, requests, urllib |
| URLs | 5 (see urls.json) |

## Median total time (ms) — lower is better

| URL | bw_fetcher | curl | curl_cffi | urllib |
|-----|-----------:|-----:|----------:|-------:|
| example.com | **122** | 135 | 124 | 120 |
| mozilla-org | **182** | 284 | 184 | 276 |
| python-org | **132** | 141 | 144 | 131 |
| wikipedia-en | **259** | 368 | 280 | 389 |
| httpbin-html | 1495 | 1108 | 816 | 1126 |

Fastest on **2/5** pages; at-par-or-better than curl-impersonate (`curl_cffi`)
on **4/5**. `curl_cffi` is the only apples-to-apples peer (it also forges a
browser TLS/HTTP2 fingerprint); the others use the platform TLS stack.

See [`README.md`](README.md) for methodology and the per-fix breakdown of what
made the optimized build fast.
