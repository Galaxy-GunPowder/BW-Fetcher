#include "platform_win.h"

#include <charconv>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_set>

#include "fetcher.h"
#include "challenge_scripts.h"
#include "URL_to_DNS/URL_Parser.h"
#include "URL_to_DNS/resolve_host.h"
#include "HTTP2_Client/http2_client.h"
#include "BORING_SSL/Boring_SSL_Client_.h"
#include "BORING_SSL/Profile_Loader/tls_profiles.h"
#include "PROXY/proxy_socket5_handshake.h"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

namespace {

bool fetch_verbose() {
    static const bool v = (std::getenv("BW_FETCHER_VERBOSE") != nullptr);
    return v;
}

struct WsaGuard {
    bool ok = false;
    WsaGuard() {
#ifdef _WIN32
        WSADATA wsa;
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#else
        ok = true;
#endif
    }
    ~WsaGuard() {
#ifdef _WIN32
        if (ok) WSACleanup();
#endif
    }
};

struct ConnectionState {
    SOCKET sock = INVALID_SOCKET;
    SSL* ssl = nullptr;
    std::string protocol;
    std::string conn_host;
    std::string conn_port;
    std::unique_ptr<Boring_SSL_Client> ssl_client;
    std::unique_ptr<nghttp2_client> client;
    std::map<std::string, std::string> cookies;
};

void absorb_set_cookie(ConnectionState& conn, const std::map<std::string, std::string>& headers) {
    for (const auto& kv : headers) {
        std::string key = kv.first;
        for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (key != "set-cookie") continue;
        const std::string& raw = kv.second;
        size_t eq = raw.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        std::string name = raw.substr(0, eq);
        size_t semi = raw.find(';', eq + 1);
        std::string value = (semi == std::string::npos)
                                ? raw.substr(eq + 1)
                                : raw.substr(eq + 1, semi - eq - 1);
        conn.cookies[name] = value;
    }
}

std::string build_cookie_header(const ConnectionState& conn) {
    if (conn.cookies.empty()) return "";
    std::ostringstream oss;
    bool first = true;
    for (const auto& kv : conn.cookies) {
        if (!first) oss << "; ";
        first = false;
        oss << kv.first << '=' << kv.second;
    }
    return oss.str();
}

std::map<std::string, std::string> merge_request_headers(
    const TLS_Config& profile,
    const std::map<std::string, std::string>& overrides) {
    std::map<std::string, std::string> out = profile.headers;
    for (const auto& kv : overrides) {
        out[kv.first] = kv.second;
    }
    return out;
}

std::map<std::string, std::string> navigation_headers() {
    return {};
}

std::map<std::string, std::string> subresource_headers(
    const std::string& referer,
    const std::string& page_host,
    const std::string& resource_host,
    const std::string& cookie) {
    std::map<std::string, std::string> h;
    h["referer"] = referer;
    h["sec-fetch-dest"] = "script";
    h["sec-fetch-mode"] = "no-cors";
    h["sec-fetch-site"] = (page_host == resource_host) ? "same-origin" : "cross-site";
    if (!cookie.empty()) h["cookie"] = cookie;
    return h;
}

void teardown_connection(ConnectionState& conn) {
    if (conn.sock != INVALID_SOCKET) set_socket_nonblocking(conn.sock, false);
    conn.client.reset();
    if (conn.ssl) {
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
        conn.ssl = nullptr;
    }
    if (conn.sock != INVALID_SOCKET) {
        closesocket(conn.sock);
        conn.sock = INVALID_SOCKET;
    }
    conn.ssl_client.reset();
    conn.protocol.clear();
    conn.conn_host.clear();
    conn.conn_port.clear();
}

FetchResult fetch_one(
    ConnectionState& conn,
    const FetchOptions& opt,
    const TLS_Config& profile,
    const std::string& start_url,
    const std::map<std::string, std::string>& header_overrides) {
    FetchResult result;
    std::string target_url = start_url;
    bool finished = false;

    for (int hop = 0; hop < opt.max_redirects && !finished; ++hop) {
        if (fetch_verbose())
            std::cerr << "\n[FETCH] Hop " << (hop + 1) << " for: " << target_url << "\n";
        result.final_url = target_url;

        ParsedURL parsed_url;
        try {
            parsed_url = parse_url(target_url);
        } catch (const std::exception& e) {
            result.error = std::string("URL parse failed: ") + e.what();
            teardown_connection(conn);
            return result;
        }

        bool reuse = conn.client && conn.ssl && conn.protocol == "h2" && !opt.proxy.enabled
                     && parsed_url.host == conn.conn_host && parsed_url.port == conn.conn_port
                     && !conn.client->goaway_received();

        if (!reuse) {
            teardown_connection(conn);

            std::string endpoint_host = opt.proxy.enabled ? opt.proxy.host : parsed_url.host;
            std::string endpoint_port = opt.proxy.enabled
                                            ? std::to_string(opt.proxy.port)
                                            : parsed_url.port;
            try {
                auto host_res = dns_lookup_host(endpoint_host, endpoint_port);
                TcpEndpoint ep = happy_eyeballs_connect(host_res);
                conn.sock = ep.sock;
            } catch (const std::exception& e) {
                result.error = std::string("connect failed: ") + e.what();
                return result;
            }
            if (fetch_verbose()) std::cerr << "Connected socket: " << conn.sock << "\n";

            if (opt.proxy.enabled) {
                if (fetch_verbose())
                    std::cerr << "[INFO] Performing SOCKS5 handshake to " << parsed_url.host
                              << " via proxy.\n";
                int target_port = 0;
                std::from_chars(parsed_url.port.data(),
                                parsed_url.port.data() + parsed_url.port.size(), target_port);
                if (target_port <= 0 || target_port > 65535) {
                    teardown_connection(conn);
                    result.error = "invalid target port: " + parsed_url.port;
                    return result;
                }
                if (!proxy_handshake(conn.sock, parsed_url.host,
                                     static_cast<uint16_t>(target_port),
                                     opt.proxy.user, opt.proxy.pass)) {
                    teardown_connection(conn);
                    result.error = "proxy handshake failed";
                    return result;
                }
                if (fetch_verbose()) std::cerr << "[INFO] Proxy tunnel established.\n";
            }

            try {
                conn.ssl_client = std::make_unique<Boring_SSL_Client>(profile);
            } catch (const std::exception& e) {
                teardown_connection(conn);
                result.error = std::string("TLS client init failed: ") + e.what();
                return result;
            }
            if (fetch_verbose())
                std::cerr << "[INFO] Starting TLS handshake for " << parsed_url.host << "...\n";
            std::tie(conn.ssl, conn.protocol) =
                conn.ssl_client->SSL_Handshake(conn.sock, parsed_url.host, profile);
            if (!conn.ssl) {
                teardown_connection(conn);
                result.error = "SSL handshake failed";
                return result;
            }

            set_socket_nonblocking(conn.sock, true);
            conn.conn_host = parsed_url.host;
            conn.conn_port = parsed_url.port;
            if (conn.protocol == "h2") {
                conn.client = std::make_unique<nghttp2_client>(conn.ssl, parsed_url.host, profile.h2);
            }
        } else if (fetch_verbose()) {
            std::cerr << "[LOOP] Reusing live connection to " << conn.conn_host
                      << " (no reconnect/handshake).\n";
        }

        auto request_start = std::chrono::steady_clock::now();

        if (conn.protocol != "h2") {
            std::cerr << "[ERROR] Protocol '" << conn.protocol
                      << "' not supported. Connection ends here.\n";
            result.error = "unsupported protocol: " + conn.protocol;
            finished = true;
            continue;
        }

        conn.client->reset_for_request();
        conn.client->on_response([&result, request_start](int32_t sid,
                                                        const nghttp2_response_class& resp) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - request_start);

            result.ok = true;
            result.headers = resp.headers;
            result.body = resp.body;
            result.ttfb_ms = duration.count();
            auto it = resp.headers.find(":status");
            if (it != resp.headers.end()) {
                int parsed = 0;
                std::from_chars(it->second.data(),
                                it->second.data() + it->second.size(), parsed);
                result.status = parsed;
            }

            if (fetch_verbose())
                std::cerr << "[MAIN] Stream " << sid << " is done! ("
                          << resp.body.size() << " bytes, " << duration.count() << "ms)\n";
        });

        auto req_headers = merge_request_headers(profile, header_overrides);
        int32_t sid = conn.client->send_header(parsed_url, req_headers);
        if (sid < 0) {
            result.error = "failed to submit HTTP/2 request";
            teardown_connection(conn);
            return result;
        }

        if (!conn.client->run_event_loop(opt.timeout_ms)) {
            result.error = "request timed out after " + std::to_string(opt.timeout_ms) + "ms";
            teardown_connection(conn);
            return result;
        }

        if (!conn.client->redirect_url.empty()) {
            if (fetch_verbose()) std::cerr << "[LOOP] Found redirect. Following...\n";
            target_url = conn.client->redirect_url;
            result.ok = false;
        } else {
            finished = true;
        }
    }

    if (!result.ok && result.error.empty()) {
        result.error = "no response captured (redirect limit reached?)";
    }
    if (result.ok) {
        absorb_set_cookie(conn, result.headers);
    }
    return result;
}

FetchResult response_to_result(
    const nghttp2_response_class& resp,
    const std::string& url,
    long long ttfb_ms,
    int32_t stream_id,
    int request_seq,
    const std::string& role,
    const std::string& discovery_source);

std::string header_value_ci(
    const std::map<std::string, std::string>& headers,
    const std::string& key) {
    for (const auto& kv : headers) {
        std::string k = kv.first;
        for (char& c : k) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (k == key) return kv.second;
    }
    return "";
}

std::string classify_content_kind(
    const std::map<std::string, std::string>& headers,
    const std::string& role) {
    std::string ct = header_value_ci(headers, "content-type");
    for (char& c : ct) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (ct.find("javascript") != std::string::npos
        || ct.find("ecmascript") != std::string::npos) {
        return "js";
    }
    if (ct.find("json") != std::string::npos) return "json";
    if (ct.find("css") != std::string::npos) return "css";
    if (ct.find("html") != std::string::npos) return "html";
    if (ct.find("wasm") != std::string::npos) return "wasm";
    if (ct.find("text/plain") != std::string::npos) return "text";
    if (ct.find("text/") == 0) return "text";
    if (role == "primary") return "html";
    return "binary";
}

FetchResult response_to_result(
    const nghttp2_response_class& resp,
    const std::string& url,
    long long ttfb_ms,
    int32_t stream_id,
    int request_seq,
    const std::string& role,
    const std::string& discovery_source) {
    FetchResult result;
    result.ok = true;
    result.final_url = url;
    result.headers = resp.headers;
    result.body = resp.body;
    result.ttfb_ms = ttfb_ms;
    result.h2_stream_id = stream_id;
    result.request_seq = request_seq;
    result.role = role;
    result.discovery_source =
        (role == "primary") ? "primary"
                            : (discovery_source.empty() ? "other" : discovery_source);
    result.content_kind = classify_content_kind(resp.headers, role);
    auto it = resp.headers.find(":status");
    if (it != resp.headers.end()) {
        int parsed = 0;
        std::from_chars(it->second.data(), it->second.data() + it->second.size(), parsed);
        result.status = parsed;
    }
    return result;
}

bool url_same_host(const std::string& url, const std::string& host) {
    try {
        return parse_url(url).host == host;
    } catch (...) {
        return false;
    }
}

struct PendingSubresource {
    std::string url;
    std::string discovery_source;
};

struct RuntimeSubresourceState {
    ConnectionState* conn = nullptr;
    const FetchOptions* opt = nullptr;
    const TLS_Config* profile = nullptr;
    MultiFetchResult* batch = nullptr;
    IncrementalSubresourceScanner scanner;
    std::deque<PendingSubresource> pending;
    std::unordered_set<std::string> pending_urls;
    std::unordered_set<std::string> dispatched;
    std::map<std::string, std::string> url_sources;
    std::map<int32_t, std::string> sid_url;
    std::map<int32_t, std::string> sid_discovery;
    std::map<int32_t, int> sid_seq;
    int32_t primary_sid = -1;
    int primary_seq = 0;
    int next_seq = 1;
    int active_streams = 0;
    bool primary_done = false;
    std::string page_url;
    std::string conn_host;
    std::chrono::steady_clock::time_point request_start{};

    RuntimeSubresourceState(const std::string& start_url, int max_subresources)
        : scanner(start_url, max_subresources), page_url(start_url) {}

    void enqueue(std::vector<DiscoveredSubresource> items) {
        for (auto& item : items) {
            if (dispatched.count(item.url) || pending_urls.count(item.url)) continue;
            pending_urls.insert(item.url);
            url_sources[item.url] = item.discovery_source;
            pending.push_back({item.url, item.discovery_source});
        }
    }

    void dispatch_same_host() {
        if (!conn || !conn->client || conn->client->goaway_received()) return;
        std::deque<PendingSubresource> deferred;
        while (!pending.empty()) {
            PendingSubresource item = std::move(pending.front());
            pending.pop_front();
            if (!url_same_host(item.url, conn_host)) {
                deferred.push_back(std::move(item));
                continue;
            }
            if (dispatched.count(item.url)) continue;
            dispatched.insert(item.url);
            pending_urls.erase(item.url);

            std::string resource_host;
            try {
                resource_host = parse_url(item.url).host;
            } catch (...) {
                resource_host = "";
            }
            std::string cookie = build_cookie_header(*conn);
            auto hdrs = subresource_headers(page_url, conn_host, resource_host, cookie);
            ParsedURL parsed;
            try {
                parsed = parse_url(item.url);
            } catch (...) {
                continue;
            }
            int32_t sid = conn->client->send_header(
                parsed, merge_request_headers(*profile, hdrs));
            if (sid < 0) continue;
            sid_url[sid] = item.url;
            sid_discovery[sid] = item.discovery_source;
            sid_seq[sid] = next_seq++;
            ++active_streams;
            if (fetch_verbose()) std::cerr << "[SUB] Stream " << sid << " GET " << item.url << "\n";
        }
        for (PendingSubresource& item : deferred) pending.push_back(std::move(item));
    }

    void on_body_chunk(int32_t sid, const uint8_t* data, size_t len) {
        if (sid != primary_sid || primary_done) return;
        enqueue(scanner.feed(reinterpret_cast<const char*>(data), len));
        dispatch_same_host();
    }

    bool on_stream_complete(int32_t sid, nghttp2_response_class& resp) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - request_start);

        if (--active_streams < 0) active_streams = 0;

        if (sid == primary_sid) {
            primary_done = true;
            absorb_set_cookie(*conn, resp.headers);
            batch->primary = response_to_result(
                resp, page_url, duration.count(), sid, primary_seq, "primary", "primary");
            enqueue(scanner.finalize());
        } else {
            auto it = sid_url.find(sid);
            std::string url = (it != sid_url.end()) ? it->second : page_url;
            if (it != sid_url.end()) sid_url.erase(it);
            std::string source = "other";
            auto src_it = sid_discovery.find(sid);
            if (src_it != sid_discovery.end()) {
                source = src_it->second;
                sid_discovery.erase(src_it);
            }
            int seq = primary_seq;
            auto seq_it = sid_seq.find(sid);
            if (seq_it != sid_seq.end()) {
                seq = seq_it->second;
                sid_seq.erase(seq_it);
            }
            batch->also.push_back(response_to_result(
                resp, url, duration.count(), sid, seq, "subresource", source));
        }

        dispatch_same_host();
        return primary_done && active_streams == 0;
    }
};

MultiFetchResult fetch_with_runtime_subresources(
    ConnectionState& conn,
    const FetchOptions& opt,
    const TLS_Config& profile) {
    MultiFetchResult batch;
    std::string target_url = opt.url;

    for (int hop = 0; hop < opt.max_redirects; ++hop) {
        if (fetch_verbose())
            std::cerr << "\n[FETCH+SUB] Hop " << (hop + 1) << " for: " << target_url << "\n";

        ParsedURL parsed_url;
        try {
            parsed_url = parse_url(target_url);
        } catch (const std::exception& e) {
            batch.primary.error = std::string("URL parse failed: ") + e.what();
            teardown_connection(conn);
            return batch;
        }

        bool reuse = conn.client && conn.ssl && conn.protocol == "h2" && !opt.proxy.enabled
                     && parsed_url.host == conn.conn_host && parsed_url.port == conn.conn_port
                     && !conn.client->goaway_received();

        if (!reuse) {
            // Reuse fetch_one's connect path by calling it would disconnect — inline connect:
            teardown_connection(conn);
            std::string endpoint_host = opt.proxy.enabled ? opt.proxy.host : parsed_url.host;
            std::string endpoint_port = opt.proxy.enabled
                                            ? std::to_string(opt.proxy.port)
                                            : parsed_url.port;
            try {
                auto host_res = dns_lookup_host(endpoint_host, endpoint_port);
                TcpEndpoint ep = happy_eyeballs_connect(host_res);
                conn.sock = ep.sock;
            } catch (const std::exception& e) {
                batch.primary.error = std::string("connect failed: ") + e.what();
                return batch;
            }
            if (opt.proxy.enabled) {
                int target_port = 0;
                std::from_chars(parsed_url.port.data(),
                                parsed_url.port.data() + parsed_url.port.size(), target_port);
                if (target_port <= 0 || target_port > 65535
                    || !proxy_handshake(conn.sock, parsed_url.host,
                                        static_cast<uint16_t>(target_port),
                                        opt.proxy.user, opt.proxy.pass)) {
                    teardown_connection(conn);
                    batch.primary.error = "proxy handshake failed";
                    return batch;
                }
            }
            try {
                conn.ssl_client = std::make_unique<Boring_SSL_Client>(profile);
            } catch (const std::exception& e) {
                teardown_connection(conn);
                batch.primary.error = std::string("TLS client init failed: ") + e.what();
                return batch;
            }
            std::tie(conn.ssl, conn.protocol) =
                conn.ssl_client->SSL_Handshake(conn.sock, parsed_url.host, profile);
            if (!conn.ssl) {
                teardown_connection(conn);
                batch.primary.error = "SSL handshake failed";
                return batch;
            }
            set_socket_nonblocking(conn.sock, true);
            conn.conn_host = parsed_url.host;
            conn.conn_port = parsed_url.port;
            if (conn.protocol == "h2") {
                conn.client = std::make_unique<nghttp2_client>(conn.ssl, parsed_url.host, profile.h2);
            }
        }

        if (conn.protocol != "h2" || !conn.client) {
            batch.primary.error = "unsupported protocol: " + conn.protocol;
            return batch;
        }

        auto state = std::make_shared<RuntimeSubresourceState>(target_url, opt.max_subresources);
        state->conn = &conn;
        state->opt = &opt;
        state->profile = &profile;
        state->batch = &batch;
        state->page_url = target_url;
        state->conn_host = conn.conn_host;
        state->request_start = std::chrono::steady_clock::now();

        conn.client->reset_for_request();
        conn.client->on_body_chunk(
            [state](int32_t sid, const uint8_t* data, size_t len) {
                state->on_body_chunk(sid, data, len);
            });
        conn.client->on_stream_complete(
            [state](int32_t sid, nghttp2_response_class& resp) {
                return state->on_stream_complete(sid, resp);
            });

        int32_t sid = conn.client->send_header(parsed_url, merge_request_headers(profile, navigation_headers()));
        if (sid < 0) {
            batch.primary.error = "failed to submit HTTP/2 request";
            teardown_connection(conn);
            return batch;
        }
        state->primary_sid = sid;
        state->primary_seq = 0;
        state->next_seq = 1;
        state->active_streams = 1;

        if (!conn.client->run_event_loop(opt.timeout_ms)) {
            batch.primary.error = "request timed out after " + std::to_string(opt.timeout_ms) + "ms";
            teardown_connection(conn);
            return batch;
        }

        if (!conn.client->redirect_url.empty()) {
            target_url = conn.client->redirect_url;
            continue;
        }

        if (!batch.primary.ok) {
            batch.primary.error = batch.primary.error.empty()
                                      ? "no response captured"
                                      : batch.primary.error;
        }

        // Cross-origin script URLs stay in ``pending`` — fetch on separate connections.
        std::unordered_set<std::string> fetched;
        for (const FetchResult& sub : batch.also) fetched.insert(sub.final_url);
        for (const PendingSubresource& pending_item : state->pending) {
            const std::string& extra_url = pending_item.url;
            if (fetched.count(extra_url)) continue;
            std::string resource_host;
            try {
                resource_host = parse_url(extra_url).host;
            } catch (...) {
                resource_host = "";
            }
            std::string cookie = build_cookie_header(conn);
            auto hdrs = subresource_headers(
                batch.primary.final_url, conn.conn_host, resource_host, cookie);
            FetchResult extra = fetch_one(conn, opt, profile, extra_url, hdrs);
            extra.request_seq = state->next_seq++;
            extra.role = "subresource";
            extra.discovery_source = pending_item.discovery_source;
            extra.content_kind = classify_content_kind(extra.headers, extra.role);
            batch.also.push_back(std::move(extra));
        }

        for (const std::string& extra_url : opt.also_fetch) {
            if (fetched.count(extra_url)) continue;
            std::string resource_host;
            try {
                resource_host = parse_url(extra_url).host;
            } catch (...) {
                resource_host = "";
            }
            std::string cookie = build_cookie_header(conn);
            auto hdrs = subresource_headers(
                batch.primary.final_url, conn.conn_host, resource_host, cookie);
            FetchResult extra = fetch_one(conn, opt, profile, extra_url, hdrs);
            extra.request_seq = state->next_seq++;
            extra.role = "subresource";
            extra.discovery_source = "manual";
            extra.content_kind = classify_content_kind(extra.headers, extra.role);
            batch.also.push_back(std::move(extra));
        }

        return batch;
    }

    batch.primary.error = "redirect limit reached";
    return batch;
}

} // namespace

FetchResult fetch(const FetchOptions& opt) {
    return fetch_multi(opt).primary;
}

MultiFetchResult fetch_multi(const FetchOptions& opt) {
    MultiFetchResult batch;

    TLS_Config profile;
    try {
        profile = load_browser_profile(opt.profile);
    } catch (const std::exception& e) {
        batch.primary.error = e.what();
        return batch;
    }
    if (fetch_verbose()) std::cerr << "[INFO] Using profile: " << profile.name << "\n";

    WsaGuard wsa;
    if (!wsa.ok) {
        batch.primary.error = "WSAStartup failed";
        return batch;
    }

    ConnectionState conn;

    if (opt.fetch_subresources) {
        batch = fetch_with_runtime_subresources(conn, opt, profile);
        teardown_connection(conn);
        return batch;
    }

    batch.primary = fetch_one(conn, opt, profile, opt.url, navigation_headers());
    if (!batch.primary.ok) {
        teardown_connection(conn);
        return batch;
    }

    std::vector<std::string> extras = opt.also_fetch;
    if (opt.auto_challenge_scripts && extras.empty()) {
        extras = discover_challenge_scripts(
            batch.primary.body, batch.primary.final_url, opt.max_challenge_scripts);
    }

    std::string page_host;
    try {
        page_host = parse_url(batch.primary.final_url).host;
    } catch (...) {
        page_host = "";
    }

    for (const std::string& extra_url : extras) {
        std::string resource_host;
        try {
            resource_host = parse_url(extra_url).host;
        } catch (...) {
            resource_host = "";
        }

        std::string cookie = build_cookie_header(conn);
        auto hdrs = subresource_headers(
            batch.primary.final_url, page_host, resource_host, cookie);

        FetchResult extra = fetch_one(conn, opt, profile, extra_url, hdrs);
        batch.also.push_back(std::move(extra));
    }

    teardown_connection(conn);
    return batch;
}
