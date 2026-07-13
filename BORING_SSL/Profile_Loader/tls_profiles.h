#pragma once
#include "tls_config.h"
#include <string>
#include <vector>

// Preset browser fingerprint profiles.
TLS_Config Chrome_143_profile();
TLS_Config Chrome_140_profile();
TLS_Config Firefox_131_profile();

// Look up a profile by name (case-insensitive). Throws std::runtime_error on an
// unknown name. Accepts both registry keys and a few friendly aliases.
TLS_Config load_browser_profile(const std::string& name);

// Names of every registered profile (for `--list-profiles`).
std::vector<std::string> list_profiles();

// --- Wire-format helpers (shared by the TLS + HTTP/2 layers) ---

// Build the length-prefixed ALPN wire form, e.g. {"h2","http/1.1"} ->
// {2,'h','2',8,'h','t','t','p','/','1','.','1'}.
std::vector<uint8_t> build_alpn_wire(const std::vector<std::string>& protocols);

// Serialize HTTP/2 SETTINGS entries into the 6-bytes-per-entry big-endian blob
// used by the TLS application_settings (ALPS) extension.
std::vector<uint8_t> build_h2_settings_blob(const std::vector<H2Setting>& settings);
