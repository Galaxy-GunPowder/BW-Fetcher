<div align="center">

# BW_Fetcher

**Fetch the web as a real browser would.**

A from-scratch C++20 HTTP/2 client that forges byte-for-byte Chrome & Firefox
fingerprints to sail past bot detection — with a `pip install`-able Python wrapper.

![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-informational)
![language](https://img.shields.io/badge/C%2B%2B-20-blue)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

Ordinary HTTP libraries — `requests`, `httpx`, plain `curl` — give themselves away the
instant they connect. Their TLS handshake and HTTP/2 settings carry a fingerprint no
browser would ever send, and modern anti-bot stacks block them on sight.

**BW_Fetcher doesn't look like a script. It looks like Chrome.** It speaks raw sockets,
encrypts with BoringSSL, negotiates HTTP/2 with nghttp2, and reproduces a real browser's
*entire* on-wire signature — cipher order, GREASE, ALPN/ALPS, post-quantum key exchange,
HTTP/2 SETTINGS and priority frames, header order and all. To the server, it's a genuine
browser.

## Get started — no compiler required

### Download & run

Grab the archive for your OS from the
[**latest release**](https://github.com/Galaxy-GunPowder/BW-TCP-Client/releases/latest),
unpack it, and run. Every dependency is bundled inside.

```powershell
# Windows
.\BW-Fetcher-win64.exe https://example.com --out -
```

```bash
# Linux
./BW-Fetcher-linux64 https://example.com --out -
```

### `pip install`

```bash
pip install bw-fetcher-py
```

The wheel bundles the native binary — nothing to build.

```python
from bw_fetcher_py import fetch

r = fetch("https://example.com", profile="Chrome143")
print(r.status, len(r.body))     # 200 1256
```

## What you get

- **Real browser fingerprints** — Chrome 143, Chrome 140, and Firefox 131 profiles that
  reproduce the complete TLS + HTTP/2 signature, not just a user-agent string.
- **Post-quantum key exchange** — `X25519MLKEM768`, matching current Chrome.
- **Gets in the door** — verified against Cloudflare, Akamai, and PerimeterX on live sites.
- **Behaves like a browser** — follows redirects, reuses connections, pulls sub-resources
  over the same HTTP/2 stream, and shuts down gracefully instead of tripping alarms.
- **SOCKS5 proxy** support with auth, and **automatic decompression** (gzip/deflate/brotli).
- **Clean output** — HTML on stdout, diagnostics on stderr. Pipe it anywhere.
- **A verdict, not just bytes** — `--report` tells you plainly whether you passed, were
  blocked, challenged, or rate-limited.

## How it works

BW_Fetcher is a from-scratch, browser-impersonating HTTP/2 client written in C++. It
drives BoringSSL's low-level primitives to craft ClientHellos that match real browsers'
JA3/JA4 TLS fingerprints, and pins per-profile HTTP/2 SETTINGS to match the Akamai H2
fingerprint — defeating TLS-based bot detection. Browser fingerprints are defined as
profiles in a registry.

## Proven in the wild

| Protection | Target | Result |
|------------|--------|--------|
| Cloudflare | applied.com | bot-score **88** ("likely human") |
| Akamai | jd.com, nike.com.br | **200 OK**, full HTML |
| PerimeterX | zillow.com | **200 OK**, full HTML (via proxy) |

See it in action: [fingerprint parity](https://www.youtube.com/watch?v=XlZMkhX4oWE) ·
[redirect chain](https://www.youtube.com/watch?v=7D1v1ealo-c).

## Fast, too

Benchmarked against `curl-impersonate` (`curl_cffi`), system `curl`, and `urllib` — median
of 3 runs on Linux:

| URL | **bw_fetcher** | curl | curl_cffi | urllib |
|-----|---------------:|-----:|----------:|-------:|
| example.com | **122 ms** | 135 | 124 | 120 |
| mozilla.org | **182 ms** | 284 | 184 | 276 |
| python.org | **132 ms** | 141 | 144 | 131 |
| wikipedia.org | **259 ms** | 368 | 280 | 389 |

At-par-or-better than `curl-impersonate` on 4 of 5 pages. Re-run it yourself with
`python benchmarks/run.py`.

## A quick tour of the CLI

```bash
BW_Fetcher --list-profiles                          # Chrome143, Chrome140, Firefox131
BW_Fetcher https://example.com --out page.html      # fetch a page
BW_Fetcher https://example.com --report -           # ...and tell me if I got blocked
BW_Fetcher https://site --proxy host:port --proxy-user u --proxy-pass p
```

Load a page *and everything it pulls in* over one connection, just like a browser:

```bash
BW_Fetcher https://example.com --fetch-subresources --out-dir captures
```

## Usage & the law

BW_Fetcher is a security-research and testing tool. Use it on your own sites, in
authorized engagements, and where you have permission. Respect target sites' terms and
applicable law.

## License

[MIT](LICENSE). A from-scratch learning and research project — built to fetch one HTML
document exactly the way a browser would.
