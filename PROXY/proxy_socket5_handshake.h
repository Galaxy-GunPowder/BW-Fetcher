#pragma once
#include "../platform_win.h"
#include <string>
#include <cstdint>

// Perform a SOCKS5 handshake and CONNECT to (target_host, target_port) over an
// already-connected socket. If user/pass are non-empty, username/password
// authentication (RFC 1929) is offered; otherwise "no authentication" is used.
// Returns true once the tunnel is established and the socket is ready for TLS.
bool proxy_handshake(SOCKET sock, const std::string& target_host, uint16_t target_port,
                     const std::string& user = "", const std::string& pass = "");
