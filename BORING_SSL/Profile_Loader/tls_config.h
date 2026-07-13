#pragma once
#include <string>
#include <map>
#include <vector>
#include <cstdint>

// ---------------------------------------------------------------------------
// A browser "profile" is everything that shapes the on-the-wire fingerprint:
//   * TLS    : cipher list, sigalgs, curves, GREASE, ALPS (application settings)
//   * ALPN   : advertised protocols ("h2", "http/1.1")
//   * HTTP/2 : SETTINGS frame entries, ALPS settings blob, window update, priority
//   * Headers: the request headers + their values (user-agent, sec-ch-ua, ...)
//
// Switching profiles therefore changes the real fingerprint, not just a label.
// ---------------------------------------------------------------------------

// Standard HTTP/2 SETTINGS identifiers (RFC 7540 / 9113). Declared here so the
// profile definitions don't need to pull in <nghttp2/nghttp2.h>.
namespace h2id {
    constexpr uint16_t HEADER_TABLE_SIZE      = 0x1;
    constexpr uint16_t ENABLE_PUSH            = 0x2;
    constexpr uint16_t MAX_CONCURRENT_STREAMS = 0x3;
    constexpr uint16_t INITIAL_WINDOW_SIZE    = 0x4;
    constexpr uint16_t MAX_FRAME_SIZE         = 0x5;
    constexpr uint16_t MAX_HEADER_LIST_SIZE   = 0x6;
}

struct H2Setting {
    uint16_t id;
    uint32_t value;
};

struct H2Profile {
    // Entries emitted in the real SETTINGS frame, in order.
    std::vector<H2Setting> frame_settings;
    // Entries advertised inside the TLS application_settings (ALPS) blob, in
    // order. Left empty for browsers that do not send ALPS (e.g. Firefox).
    std::vector<H2Setting> alps_settings;
    // Connection-level WINDOW_UPDATE increment sent on stream 0 (0 => skip).
    uint32_t connection_window_increment = 0;

    // Request priority (HTTP/2 PRIORITY spec). When send_priority is false the
    // request is submitted without a priority spec.
    bool    send_priority      = false;
    int32_t priority_dep       = 0;
    int32_t priority_weight    = 256;
    bool    priority_exclusive = true;
};

struct TLS_Config {
    std::string name;

    // --- TLS knobs ---
    std::string cipher_list;
    std::string sigalgs_list;
    std::string curve_list;
    bool grease_switch        = true;
    bool application_settings = true;   // send TLS ALPS extension for h2

    // ALPN protocols, in preference order (e.g. {"h2", "http/1.1"}).
    std::vector<std::string> alpn_protocols = {"h2", "http/1.1"};

    // --- HTTP/2 + headers ---
    H2Profile h2;
    std::map<std::string, std::string> headers;
};
