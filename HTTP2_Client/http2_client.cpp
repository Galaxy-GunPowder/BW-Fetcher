#include "http2_client.h"
#include "../decompress.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>
#include <cstdlib>

// High-volume per-header / per-write tracing is off unless BW_FETCHER_VERBOSE is
// set. These logs fire dozens of times per fetch and each std::endl flush is a
// syscall, so gating them keeps the hot path cheap (and stderr clean).
static bool h2_verbose() {
    static const bool v = (std::getenv("BW_FETCHER_VERBOSE") != nullptr);
    return v;
}


nghttp2_client::nghttp2_client(SSL* ssl, const std::string& host, const H2Profile& h2)
    : ssl(ssl), host(host), h2_profile(h2), _running(true), redirect_url("")    {
    nghttp2_session_callbacks* callbacks;
    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback2(callbacks, nghttp2_client::nghttp2_sending_callback);
    nghttp2_session_callbacks_set_recv_callback2(callbacks, nghttp2_client::socket_recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, nghttp2_client::on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, nghttp2_client::on_body_rec_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, nghttp2_client::on_header_callback);

    int rv = nghttp2_session_client_new(&session, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0) {
        std::cerr << "[ERROR] nghttp2_session_client_new failed" << std::endl;
        return;
    }

    //-- Settings FRAME (driven by the browser profile) --
    std::vector<nghttp2_settings_entry> iv;
    iv.reserve(h2_profile.frame_settings.size());
    for (const auto& s : h2_profile.frame_settings) {
        iv.push_back({static_cast<int32_t>(s.id), s.value});
    }

    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv.data(),
                                 static_cast<size_t>(iv.size()));
    if (rv != 0) {
        std::cerr << "Fatal error: nghttp2_submit_settings returned " << rv << std::endl;
    }

    // Connection-level WINDOW UPDATE (stream 0), if the profile sends one.
    if (h2_profile.connection_window_increment > 0) {
        nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0,
                                     static_cast<int32_t>(h2_profile.connection_window_increment));
    }

    nghttp2_session_send(session);
}

nghttp2_client::~nghttp2_client() {
    graceful_close();
    if (session) {
        nghttp2_session_del(session);
        session = nullptr;
    }
}

void nghttp2_client::reset_for_request() {
    // Re-arm the loop for another request on the same live session. _goaway is
    // intentionally NOT cleared — it reflects the connection's permanent state.
    _running = true;
    redirect_url.clear();
    body_chunk_cb = nullptr;
    stream_complete_cb = nullptr;
    response_cb = nullptr;
    // Drop captured responses from prior hops on this connection; the next
    // request gets a fresh stream id, so old entries are just dead weight.
    http2_responses.clear();
}

void nghttp2_client::graceful_close() {
    if (!session) return;
    // Send a GOAWAY(NO_ERROR) and flush it so the server sees a clean shutdown
    // instead of an abrupt TCP RST (which anti-bot stacks may flag).
    nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    nghttp2_session_send(session);
}

void nghttp2_client::perform_decompression(int32_t sid) {
    auto& resp = http2_responses[sid];
    std::string encoding = "";

    if (resp.headers.count("content-encoding")) encoding = resp.headers["content-encoding"];
    else if (resp.headers.count("Content-Encoding")) encoding = resp.headers["Content-Encoding"];

    if (encoding == "gzip" || encoding == "deflate") {
        resp.body = ::decompress_gzip_deflate(resp.body); // Use global function
    } else if (encoding == "br") {
        resp.body = ::decompress_brotli(resp.body); // Use global function
    } else if (encoding == "zstd") {
        // zstd is advertised in accept-encoding ONLY to match Chrome's real
        // fingerprint (dropping it would change the request and defeat the
        // point of this client). We do not currently decode zstd, so if a
        // server actually picks it we leave the body untouched and warn loudly
        // rather than silently returning compressed bytes. Servers rarely
        // choose zstd for HTML; add a libzstd path here if that changes.
        std::cerr << "[WARN] Response is zstd-encoded; BW_Fetcher does not "
                     "decode zstd. Body is returned compressed.\n";
    } else if (!encoding.empty()) {
        std::cerr << "[WARN] Unknown content-encoding '" << encoding
                  << "'; body returned as-is.\n";
    }
}

int nghttp2_client::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<nghttp2_client*>(user_data);
    int32_t sid = frame->hd.stream_id;


    // Log the frame type for debugging
    // Type 7 = GOAWAY, Type 1 = HEADERS, Type 0 = DATA
    if (frame->hd.type == NGHTTP2_GOAWAY) {
        if (h2_verbose())
            std::cerr << "[GOAWAY] Received! Error Code: " << frame->goaway.error_code
                      << " Last Stream ID: " << frame->goaway.last_stream_id << std::endl;
        self->_goaway = true;   // connection can no longer take new streams
        self->_running = false;
        return 0;
    }

    if (sid > 0 && (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA)) {
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            if (h2_verbose()) std::cerr << "[Stream " << sid << "] END_STREAM detect." << std::endl;
            auto& resp = self->http2_responses[sid];
            const std::string& status = resp.headers[":status"];

            // A 3xx WITH a Location is a redirect we follow on the next loop
            // iteration; everything else (200, but also 403/404/429/5xx — the
            // very responses an anti-bot probe cares about) is a terminal
            // response we must decompress and hand back to the caller.
            const bool is_redirect =
                (status == "301" || status == "302" || status == "303" ||
                 status == "307" || status == "308") &&
                resp.headers.count("location");

            if (is_redirect) {
                std::string loc = resp.headers["location"];
                if (h2_verbose()) std::cerr << "[DEBUG] Redirect RAW Location " << loc << std::endl;
                // Resolve relative Location targets against the current host.
                if (loc.rfind("//", 0) == 0) {
                    loc = "https:" + loc;                       // scheme-relative
                } else if (!loc.empty() && loc[0] == '/') {
                    loc = "https://" + self->host + loc;        // root-relative
                }
                self->redirect_url = loc;
                if (h2_verbose()) std::cerr << "[DEBUG] FIXED URL " << loc << std::endl;
                self->_running = false;
            } else {
                self->perform_decompression(sid);
                bool stop = true;
                if (self->stream_complete_cb) {
                    stop = self->stream_complete_cb(sid, resp);
                } else if (self->response_cb) {
                    self->response_cb(sid, resp);
                }
                if (stop) self->_running = false;
            }
        }
    }
    return 0;
}

int nghttp2_client::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame,
                                       const uint8_t* name, size_t namelen,
                                       const uint8_t* value, size_t valuelen,
                                       uint8_t flags, void* user_data) {
    auto* self = static_cast<nghttp2_client*>(user_data);
    std::string k((char*)name, namelen), v((char*)value, valuelen);
    if (frame->hd.type == NGHTTP2_HEADERS) {
        self->http2_responses[frame->hd.stream_id].headers[k] = v;
        if (h2_verbose()) std::cerr << " [Header] " << k << ": " << v << '\n';
    }
    return 0;
}

void nghttp2_client::on_response(ResponseCallback cb) {
    response_cb = std::move(cb);
    stream_complete_cb = nullptr;
}

int nghttp2_client::on_body_rec_callback(nghttp2_session* session, uint8_t, int32_t sid, const uint8_t* data, size_t len, void* user_data) {
    auto* self = static_cast<nghttp2_client*>(user_data);
    self->http2_responses[sid].body.append((char*)data, len);
    if (self->body_chunk_cb) self->body_chunk_cb(sid, data, len);
    // 1. Consume the specific stream (Stream ID)
    nghttp2_session_consume(session, sid, len);

    // 2. Consume the connection (Stream 0)
    // This tells the server the overall pipe is clear.
    nghttp2_session_consume_connection(session, len);

    return 0;
}

ssize_t nghttp2_client::socket_recv_callback(nghttp2_session*, uint8_t* buf, size_t length, int, void* user_data) {
    auto* self = static_cast<nghttp2_client*>(user_data);
    int n = SSL_read(self->ssl, buf, (int)length);

    if (n > 0) return n;

    int err = SSL_get_error(self->ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }

    if (err == SSL_ERROR_ZERO_RETURN) {
        if (h2_verbose()) std::cerr << "[DEBUG] SSL connection closed by server." << std::endl;
        return 0; // Return 0 to tell nghttp2 this is EOF
    }

    std::cerr << "[DEBUG] SSL_read fatal error: " << err << std::endl;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

ssize_t nghttp2_client::nghttp2_sending_callback(nghttp2_session*, const uint8_t* data, size_t length, int, void* user_data) {
    auto* self = static_cast<nghttp2_client*>(user_data);
    int n = SSL_write(self->ssl, data, (int)length);
    if (n > 0) {
        if (h2_verbose()) std::cerr << "[DEBUG] SSL_write: sent " << n << " bytes.\n";
        return n;
    }
    int err = SSL_get_error(self->ssl, n);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) return NGHTTP2_ERR_WOULDBLOCK;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

int32_t nghttp2_client::send_header(const ParsedURL& parsed_url, const std::map<std::string, std::string>& headers) {
    // 1. Define pseudo-headers as explicit local variables so they stay alive
    std::string m_key = ":method", m_val = "GET";
    std::string s_key = ":scheme", s_val = "https";
    std::string p_key = ":path",   p_val = parsed_url.path;
    if (!parsed_url.query.empty()) {
        p_val += "?" + parsed_url.query; // read only, allowed
    }
    std::string a_key = ":authority", a_val = host;

    // Remove port from authority if present (GitHub/Fastly requirement)
    size_t colon = a_val.find(':');
    if (colon != std::string::npos) a_val = a_val.substr(0, colon);

    // 2. Prepare the NV array
    std::vector<nghttp2_nv> nva;
    auto add_nv = [&](const std::string& k, const std::string& v) {
        nva.push_back({
            (uint8_t*)k.c_str(), (uint8_t*)v.c_str(),
            k.size(), v.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    };

    // 3. Add headers
    add_nv(m_key, m_val);
    add_nv(s_key, s_val);
    add_nv(a_key, a_val);
    add_nv(p_key, p_val);

    for (auto const& [k, v] : headers) {
        add_nv(k, v);
    }

    // Setup the HTTP/2 PRIORITY spec when the profile uses one (this triggers
    // the 0x20 flag and the extra 5 bytes in the HEADERS frame, like Chrome).
    nghttp2_priority_spec pri_spec;
    nghttp2_priority_spec* pri_ptr = nullptr;
    if (h2_profile.send_priority) {
        nghttp2_priority_spec_init(&pri_spec,
                                   h2_profile.priority_dep,
                                   h2_profile.priority_weight,
                                   h2_profile.priority_exclusive ? 1 : 0);
        pri_ptr = &pri_spec;
    }

    int32_t sid = nghttp2_submit_request(session, pri_ptr, nva.data(), nva.size(), nullptr, nullptr);

    if (sid >= 0) {
        nghttp2_session_send(session);
    }
    return sid;
}


bool nghttp2_client::run_event_loop(int timeout_ms) {
    const SOCKET fd = (SOCKET)SSL_get_fd(ssl);
    const auto start = std::chrono::steady_clock::now();
    while (_running) {
        // 0. Bail out if the overall deadline has passed. Without this a server
        //    that opens our stream but never sends END_STREAM (slowloris, a
        //    stalled body) would keep us in this loop forever.
        if (timeout_ms > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) {
                std::cerr << "[ERROR] Event loop timed out after " << timeout_ms
                          << "ms (no terminal response).\n";
                return false;
            }
        }

        // 1. Process all incoming data from the server
        int r = nghttp2_session_recv(session);
        if (r != 0 && r != NGHTTP2_ERR_WOULDBLOCK) break;

        // 2. Clear the outgoing queue (sends ACKs, PONGs, and Requests)
        int s = nghttp2_session_send(session);
        if (s != 0 && s != NGHTTP2_ERR_WOULDBLOCK) break;

        // 3. Nothing left to do this iteration: block on the socket until it is
        //    readable instead of busy-polling with a fixed sleep. This wakes the
        //    instant the response arrives (lower latency) and burns no CPU while
        //    waiting. SSL_pending guards against decrypted bytes already buffered
        //    inside BoringSSL that poll() would not see. The wait is clamped to
        //    the remaining time so the deadline above stays accurate.
        if (r == NGHTTP2_ERR_WOULDBLOCK && s == NGHTTP2_ERR_WOULDBLOCK) {
            if (SSL_pending(ssl) > 0) continue;
            int wait_ms = 1000; // also caps how long until _running changes are seen
            if (timeout_ms > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now() - start).count();
                long long remaining = static_cast<long long>(timeout_ms) - elapsed;
                if (remaining <= 0) continue; // re-check deadline at top of loop
                wait_ms = static_cast<int>(std::min<long long>(wait_ms, remaining));
            }
            wait_readable(fd, wait_ms);
        }
    }
    return true;
}