#pragma once
#include "../platform_win.h"
#include <map>
#include <string>
#include <queue>
#include <mutex>
#include <vector>
#include <atomic>
#include <functional>
#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include "../URL_to_DNS/URL_Parser.h"
#include "../BORING_SSL/Profile_Loader/tls_config.h"

struct nghttp2_response_class {
    std::map<std::string, std::string> headers;
    std::string body;
};

using ResponseCallback = std::function<void(int32_t sid, const nghttp2_response_class& resp)>;
using BodyChunkCallback = std::function<void(int32_t sid, const uint8_t* data, size_t len)>;
// Return true to stop the event loop after this stream completes.
using StreamCompleteCallback = std::function<bool(int32_t sid, nghttp2_response_class& resp)>;

class nghttp2_client {
public:
    std::string redirect_url = "";
    nghttp2_client(SSL* ssl, const std::string& host, const H2Profile& h2);
    ~nghttp2_client();

    int32_t send_header(const ParsedURL& parsed_url, const std::map<std::string, std::string>& headers = {});
    void on_response(ResponseCallback cb);
    void on_body_chunk(BodyChunkCallback cb) { body_chunk_cb = std::move(cb); }
    void on_stream_complete(StreamCompleteCallback cb) {
        stream_complete_cb = std::move(cb);
        response_cb = nullptr;
    }
    // Pump the session until a terminal response / redirect / GOAWAY is seen.
    // timeout_ms caps the total wait (<= 0 = no cap). Returns false ONLY when it
    // bailed out on the timeout, so the caller can report a clean error instead
    // of hanging on a server that never finishes the stream.
    bool run_event_loop(int timeout_ms = 30000);
    // Politely tear the session down (flushes a GOAWAY to the server) once the
    // wanted response has been captured. Safe to call multiple times.
    void graceful_close();

    // Re-arm the loop to issue another request on the SAME connection (used to
    // follow a same-host redirect without a fresh socket + TLS handshake).
    void reset_for_request();
    // True once the server has sent a GOAWAY: the session can no longer accept
    // new streams, so the connection must not be reused.
    bool goaway_received() const { return _goaway; }

private:
    SSL* ssl;
    std::string host;
    H2Profile h2_profile;
    nghttp2_session* session = nullptr;
    std::atomic<bool> _running{true};
    bool _goaway = false;
    std::map<int32_t, nghttp2_response_class> http2_responses;
    ResponseCallback response_cb;
    BodyChunkCallback body_chunk_cb;
    StreamCompleteCallback stream_complete_cb;

    // --- Decompression Helper (Now internal to this class) ---
    void perform_decompression(int32_t stream_id);

    // --- nghttp2 Callbacks ---
    static ssize_t socket_recv_callback(nghttp2_session* session, uint8_t* buf, size_t length, int flags, void* user_data);
    static ssize_t nghttp2_sending_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
    static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
    static int on_body_rec_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data);
    static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
};