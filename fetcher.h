#pragma once
#include <string>
#include <map>
#include <vector>
#include <cstdint>

// ---------------------------------------------------------------------------
// Reusable fetch core. main.cpp (the CLI) and any other front-end drive the
// fetcher exclusively through fetch()/fetch_multi(); none of the request state
// is hardcoded.
// ---------------------------------------------------------------------------

struct ProxyConfig {
    bool        enabled = false;
    std::string host;
    uint16_t    port = 0;
    std::string user;
    std::string pass;
};

struct FetchOptions {
    std::string              url;
    std::vector<std::string> also_fetch;  // extra GETs after primary (same connection when same host)
    bool                     auto_challenge_scripts = false;  // discover + fetch vendor-like script URLs
    int                      max_challenge_scripts = 5;
    bool                     fetch_subresources = false;  // scan HTML as it arrives, GET script URLs
    int                      max_subresources = 32;
    std::string              profile = "Chrome143";   // see list_profiles()
    ProxyConfig              proxy;
    int                      max_redirects = 5;
    // Wall-clock cap for a single request's event loop, in milliseconds. Bounds
    // a stalled / slowloris server that opens a stream and never sends
    // END_STREAM (which would otherwise hang the loop forever). <= 0 disables.
    int                      timeout_ms = 30000;
};

struct FetchResult {
    bool                                ok = false;
    std::string                         error;     // populated when ok == false
    int                                 status = 0; // final HTTP status
    std::map<std::string, std::string>  headers;
    std::string                         body;      // decompressed response body
    std::string                         final_url; // URL after following redirects
    long long                           ttfb_ms = 0;
    int32_t                             h2_stream_id = -1;  // HTTP/2 stream, or -1 if unknown
    int                                 request_seq = 0;  // 0=primary, then 1..N in start order
    std::string                         role;               // "primary" | "subresource"
    // HTML discovery path: primary | script | link/preload | link/modulepreload | manual
    std::string                         discovery_source;
    // Response Content-Type bucket: html | js | css | json | wasm | text | binary
    std::string                         content_kind;
};

struct MultiFetchResult {
    FetchResult              primary;
    std::vector<FetchResult> also;  // one entry per also_fetch URL, same order
};

// Perform a single fetch, following up to opt.max_redirects redirects. All
// diagnostics are written to std::cerr so the body is the only payload a caller
// needs to capture. Manages WSAStartup/WSACleanup internally.
FetchResult fetch(const FetchOptions& opt);

// Fetch primary URL then each ``also_fetch`` entry, reusing the live HTTP/2
// connection for same-host hops. Forwards Set-Cookie values and sends Referer
// on subresource requests.
MultiFetchResult fetch_multi(const FetchOptions& opt);
