#include "../platform_win.h"
#include "Boring_SSL_Client_.h"

#include <openssl/err.h>
#include <cstdlib>
#include <iostream>

#include <vector>
#include <sstream>
#include <stdexcept>

// Gate chatty per-handshake tracing behind BW_FETCHER_VERBOSE (mirrors the
// other translation units). Failures/warnings below stay unconditional.
static bool tls_verbose() {
    static const bool v = (std::getenv("BW_FETCHER_VERBOSE") != nullptr);
    return v;
}

#ifndef NID_X25519_MLKEM768
#define NID_X25519_MLKEM768 1214 // The internal BoringSSL NID for 4588
#endif
#ifdef _WIN32
// NOTE: no WinHttp/Cert/Crypt API is actually called here; these are kept
// guarded for Windows builds only so the POSIX build does not need them.
#include <winhttp.h>
#include <wincrypt.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#endif

#include <string>
#include "compresser/brotili_cert_compress.h"
#include "Profile_Loader/tls_profiles.h"

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

Boring_SSL_Client::Boring_SSL_Client(const TLS_Config& cfg) {
    SSL_library_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        // Throw rather than std::exit: fetch() is a reusable core that reports
        // failures via FetchResult, and a library must never kill the process.
        throw std::runtime_error("Failed to create SSL_CTX");
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);


    if (SSL_CTX_set1_sigalgs_list(ctx, cfg.sigalgs_list.c_str()) != 1) {
        // A wrong sigalgs list silently changes the TLS fingerprint, which
        // defeats the entire purpose of this client — fail loudly like the
        // cipher list does rather than continuing with a degraded handshake.
        SSL_CTX_free(ctx);
        ctx = nullptr;
        throw std::runtime_error("Failed to set signature algorithms");
    }

    // --- 1. CIPHER ----
    if (SSL_CTX_set_cipher_list(ctx, cfg.cipher_list.c_str()) != 1) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
        throw std::runtime_error("Failed to set cipher list");
    }

    // --- 2. COMMON SIGNED CERT TIMESTAMPS & OCSP ---
    SSL_CTX_enable_signed_cert_timestamps(ctx);
    SSL_CTX_enable_ocsp_stapling(ctx);
    // --- 3. UNIQUE CHROME - ENABLE GREASE ---
    SSL_CTX_set_grease_enabled(ctx, cfg.grease_switch ? 1 : 0);
    // --- 4. CURVES
    if (SSL_CTX_set1_curves_list(ctx, cfg.curve_list.c_str()) != 1) {
        std::cerr << "Current Curve List not supported";
    }

    // --- 5. COMPRESSED CERT
    int ok = SSL_CTX_add_cert_compression_alg(
    ctx,
    2,  // brotli
    nullptr,
    brotli_decompress_cb
);

    if (ok != 1) {
        std::cerr << "[WARN] Brotli cert compression not available\n";
    }

}

Boring_SSL_Client::~Boring_SSL_Client() {
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
}

std::pair<SSL*, std::string> Boring_SSL_Client::SSL_Handshake(SOCKET sock, const std::string& host, const TLS_Config& cfg)
{

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Failed to create SSL object\n";
        return {nullptr, ""};
    }

    // ---- 6. SNI ---------
    if (tls_verbose()) std::cerr << "[DEBUG] host.c_str() = '" << host.c_str() << "'" << std::endl;
    SSL_set_tlsext_host_name(ssl, host.c_str());

    // -----8. ALPN ------------------
    std::vector<uint8_t> alpn = build_alpn_wire(cfg.alpn_protocols);
    SSL_set_alpn_protos(ssl, alpn.data(), static_cast<unsigned int>(alpn.size()));

    // -----9. application_settings (RFC 8444 / ALPS) for h2 -----------
    if (cfg.application_settings) {
        std::vector<uint8_t> alps_blob = build_h2_settings_blob(cfg.h2.alps_settings);
        if (!SSL_add_application_settings(
                ssl,
                reinterpret_cast<const uint8_t*>("h2"), 2,    // ALPN protocol id and length
                alps_blob.data(), alps_blob.size())) {        // profile SETTINGS payload
            std::cerr << "[WARN] Failed to add application_settings for h2\n";
                }
    }

    ERR_clear_error();

    // ======== CONNECT SERVER
    // BIND fd connection. BoringSSL's BIO_fd API is int-typed; narrowing the
    // Win64 SOCKET here is safe (Windows socket handles are guaranteed to fit in
    // an int for these APIs), unlike a raw int field that could truncate a real
    // handle — see TcpEndpoint::sock which is kept as SOCKET for that reason.
    SSL_set_fd(ssl, (int)sock);
    // CONNECT
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        unsigned long err = ERR_get_error();
        std::cerr << "TLS handshake failed: " << ERR_error_string(err, nullptr) << "\n";
        SSL_free(ssl);
        return {nullptr, ""};
    }

    // RETURN ALPN
    const unsigned char* proto = nullptr;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);
    std::string protocol = (proto && proto_len > 0) ? std::string(reinterpret_cast<const char*>(proto), proto_len) : "";
    if (tls_verbose()) std::cerr << "Negotiated ALPN: " << protocol << std::endl;
    return {ssl, protocol};
}
