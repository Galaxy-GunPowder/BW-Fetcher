#include "URL_Parser.h"
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

// Per-URL trace is off unless BW_FETCHER_VERBOSE is set. It is gated not just to
// cut noise but because the query string (printed below) routinely carries
// tokens / API keys we must not spill into logs by default.
static bool url_verbose() {
    static const bool v = (std::getenv("BW_FETCHER_VERBOSE") != nullptr);
    return v;
}

static bool is_scheme_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) ||
           c == '+' || c == '-' || c == '.';
}

ParsedURL parse_url(const std::string& uri, const std::string& default_port) {
    ParsedURL u;
    size_t i = 0;
    const size_t n = uri.size();

    // ===== 1. Parse scheme =====
    if (n == 0 || !std::isalpha(static_cast<unsigned char>(uri[0])))
        throw std::runtime_error("Invalid URI: scheme");

    while (i < n && is_scheme_char(uri[i])) i++;

    if (i >= n || uri[i] != ':')
        throw std::runtime_error("Invalid URI: missing ':'");

    u.scheme = uri.substr(0, i);
    i++; // skip ':'

    // ===== 2. Check for authority =====
    bool has_authority = (i + 1 < n && uri[i] == '/' && uri[i + 1] == '/');
    if (has_authority) {
        i += 2;
        size_t auth_end = uri.find_first_of("/?#", i);
        if (auth_end == std::string::npos)
            auth_end = n;

        std::string authority = uri.substr(i, auth_end - i);
        i = auth_end;

        // ---- userinfo ----
        size_t at = authority.find('@');
        if (at != std::string::npos) {
            u.userinfo = authority.substr(0, at);
            authority = authority.substr(at + 1);
        }

        // ---- host + port (IPv6 safe) ----
        if (!authority.empty() && authority[0] == '[') {
            size_t close = authority.find(']');
            if (close == std::string::npos)
                throw std::runtime_error("Invalid IPv6 literal");
            u.host = authority.substr(1, close - 1);
            if (close + 1 < authority.size() && authority[close + 1] == ':')
                u.port = authority.substr(close + 2);
        } else {
            size_t colon = authority.rfind(':');
            if (colon != std::string::npos && authority.find(':') == colon) {
                u.host = authority.substr(0, colon);
                u.port = authority.substr(colon + 1);
            } else {
                u.host = authority;
            }
        }
    }

    // ===== 3. Parse path =====
    size_t path_start = i;
    size_t path_end = uri.find_first_of("?#", i);
    if (path_end == std::string::npos)
        path_end = n;

    u.path = uri.substr(path_start, path_end - path_start);

    // --- MOVE I FORWARD ---
    i = path_end; // <--- ADD THIS LINE!

    if (u.path.empty()) {
        u.path = "/";
    }

    // ===== 4. Parse query =====
    // Now 'i' is correctly pointing at '?' or '#' or end of string
    if (i < n && uri[i] == '?') {
        i++; // skip '?'
        size_t query_end = uri.find('#', i);
        if (query_end == std::string::npos)
            query_end = n;
        u.query = uri.substr(i, query_end - i);
        i = query_end; // Move 'i' to '#' or end
    }

    // ===== 5. Parse fragment =====
    if (i < n && uri[i] == '#') {
        u.fragment = uri.substr(i + 1);
    }

    // ===== 6. Assign default port if missing =====
    if (u.port.empty()) {
        if (!default_port.empty())
            u.port = default_port;
        else if (u.scheme == "https")
            u.port = "443";
        else if (u.scheme == "http")
            u.port = "80";
    }

    // ===== Debug output (stderr: stdout is reserved for the payload) =====
    if (url_verbose()) {
        std::cerr << "===== Parsed URL =====\n";
        std::cerr << "Scheme   : " << u.scheme << "\n";
        std::cerr << "Userinfo : " << (u.userinfo.empty() ? "(none)" : u.userinfo) << "\n";
        std::cerr << "Host     : " << (u.host.empty() ? "(none)" : u.host) << "\n";
        std::cerr << "Port     : " << (u.port.empty() ? "(none)" : u.port) << "\n";
        std::cerr << "Path     : " << (u.path.empty() ? "(empty)" : u.path) << "\n";
        std::cerr << "Query    : " << (u.query.empty() ? "(none)" : u.query) << "\n";
        std::cerr << "Fragment : " << (u.fragment.empty() ? "(none)" : u.fragment) << "\n";
        std::cerr << "======================\n";
    }

    return u;
}
