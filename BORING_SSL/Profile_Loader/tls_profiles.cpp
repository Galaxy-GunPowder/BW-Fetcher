#include "tls_profiles.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <map>
#include <stdexcept>

// ===========================================================================
// Wire-format helpers
// ===========================================================================
std::vector<uint8_t> build_alpn_wire(const std::vector<std::string>& protocols) {
    std::vector<uint8_t> out;
    for (const auto& p : protocols) {
        out.push_back(static_cast<uint8_t>(p.size()));
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

std::vector<uint8_t> build_h2_settings_blob(const std::vector<H2Setting>& settings) {
    std::vector<uint8_t> out;
    out.reserve(settings.size() * 6);
    for (const auto& s : settings) {
        out.push_back(static_cast<uint8_t>((s.id >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(s.id & 0xFF));
        out.push_back(static_cast<uint8_t>((s.value >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((s.value >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((s.value >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(s.value & 0xFF));
    }
    return out;
}

// ===========================================================================
// Profiles
// ===========================================================================
TLS_Config Chrome_143_profile() {
    TLS_Config cfg;
    cfg.name = "Chrome143";

    cfg.sigalgs_list =
        "ecdsa_secp256r1_sha256:"
        "rsa_pss_rsae_sha256:"
        "rsa_pkcs1_sha256:"
        "ecdsa_secp384r1_sha384:"
        "rsa_pss_rsae_sha384:"
        "rsa_pkcs1_sha384:"
        "rsa_pss_rsae_sha512:"
        "rsa_pkcs1_sha512";

    cfg.cipher_list =
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-SHA:"
        "AES256-SHA";

    cfg.grease_switch        = true;
    cfg.curve_list           = "X25519MLKEM768:X25519:P-256:P-384";
    cfg.application_settings = true;
    cfg.alpn_protocols       = {"h2", "http/1.1"};

    // SETTINGS frame actually sent on the wire (matches the original client).
    cfg.h2.frame_settings = {
        {h2id::HEADER_TABLE_SIZE,    65536},
        {h2id::ENABLE_PUSH,          0},
        {h2id::INITIAL_WINDOW_SIZE,  6291456},
        {h2id::MAX_HEADER_LIST_SIZE, 262144},
    };
    // ALPS settings advertised inside the TLS handshake.
    cfg.h2.alps_settings = {
        {h2id::HEADER_TABLE_SIZE,      65536},
        {h2id::ENABLE_PUSH,            0},
        {h2id::MAX_CONCURRENT_STREAMS, 1000},
        {h2id::INITIAL_WINDOW_SIZE,    6291456},
        {h2id::MAX_FRAME_SIZE,         16384},
        {h2id::MAX_HEADER_LIST_SIZE,   262144},
    };
    cfg.h2.connection_window_increment = 15663105;
    cfg.h2.send_priority      = true;
    cfg.h2.priority_dep       = 0;
    cfg.h2.priority_weight    = 256;
    cfg.h2.priority_exclusive = true;

    cfg.headers = {
        {"sec-ch-ua", "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\""},
        {"sec-ch-ua-mobile", "?0"},
        {"sec-ch-ua-platform", "\"Windows\""},
        {"upgrade-insecure-requests", "1"},
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "none"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-user", "?1"},
        {"sec-fetch-dest", "document"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"accept-language", "en-US,en;q=0.9"},
        {"priority", "u=0, i"},
    };
    return cfg;
}

TLS_Config Chrome_140_profile() {
    // Chrome 140 shares the 143 TLS/HTTP-2 fingerprint; the visible change is
    // the advertised version in the UA / client-hint headers.
    TLS_Config cfg = Chrome_143_profile();
    cfg.name = "Chrome140";
    cfg.headers["sec-ch-ua"] =
        "\"Chromium\";v=\"140\", \"Google Chrome\";v=\"140\", \"Not?A_Brand\";v=\"24\"";
    cfg.headers["user-agent"] =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    return cfg;
}

TLS_Config Firefox_131_profile() {
    TLS_Config cfg;
    cfg.name = "Firefox131";

    // Firefox sigalg order differs from Chrome and includes SHA-1 legacy algs.
    cfg.sigalgs_list =
        "ecdsa_secp256r1_sha256:"
        "ecdsa_secp384r1_sha384:"
        "ecdsa_secp521r1_sha512:"
        "rsa_pss_rsae_sha256:"
        "rsa_pss_rsae_sha384:"
        "rsa_pss_rsae_sha512:"
        "rsa_pkcs1_sha256:"
        "rsa_pkcs1_sha384:"
        "rsa_pkcs1_sha512:"
        "ecdsa_sha1:"
        "rsa_pkcs1_sha1";

    // Firefox cipher ordering.
    cfg.cipher_list =
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES256-SHA:"
        "ECDHE-ECDSA-AES128-SHA:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-SHA:"
        "AES256-SHA";

    cfg.grease_switch        = false;   // Firefox does not send GREASE
    cfg.curve_list           = "X25519MLKEM768:X25519:P-256:P-384:P-521";
    cfg.application_settings = false;   // Firefox does not send TLS ALPS
    cfg.alpn_protocols       = {"h2", "http/1.1"};

    // Firefox SETTINGS: header table, initial window, max frame size.
    cfg.h2.frame_settings = {
        {h2id::HEADER_TABLE_SIZE,   65536},
        {h2id::INITIAL_WINDOW_SIZE, 131072},
        {h2id::MAX_FRAME_SIZE,      16384},
    };
    cfg.h2.alps_settings = {};          // no ALPS
    cfg.h2.connection_window_increment = 12517377;
    cfg.h2.send_priority = false;       // Firefox builds a priority tree we don't model

    cfg.headers = {
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
        {"accept-language", "en-US,en;q=0.5"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"upgrade-insecure-requests", "1"},
        {"sec-fetch-dest", "document"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-site", "none"},
        {"sec-fetch-user", "?1"},
        {"priority", "u=0, i"},
    };
    return cfg;
}

// ===========================================================================
// Registry
// ===========================================================================
namespace {
const std::map<std::string, std::function<TLS_Config()>>& registry() {
    static const std::map<std::string, std::function<TLS_Config()>> r = {
        {"chrome143", &Chrome_143_profile},
        {"chrome140", &Chrome_140_profile},
        {"firefox131", &Firefox_131_profile},
        // friendly aliases
        {"chrome", &Chrome_143_profile},
        {"firefox", &Firefox_131_profile},
    };
    return r;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
} // namespace

TLS_Config load_browser_profile(const std::string& name) {
    auto it = registry().find(to_lower(name));
    if (it == registry().end()) {
        std::string known;
        for (const auto& kv : registry()) {
            if (!known.empty()) known += ", ";
            known += kv.first;
        }
        throw std::runtime_error("Unknown TLS profile: '" + name + "'. Known: " + known);
    }
    return it->second();
}

std::vector<std::string> list_profiles() {
    // Only the canonical (non-alias) names, deduplicated by produced profile name.
    return {"Chrome143", "Chrome140", "Firefox131"};
}
