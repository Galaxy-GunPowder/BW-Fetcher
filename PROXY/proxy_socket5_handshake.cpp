#include "proxy_socket5_handshake.h"

#include <iostream>
#include <vector>

namespace {

// recv() may return fewer bytes than requested even on a blocking socket, so
// loop until exactly `len` bytes are read (or the peer closes / errors).
bool recv_exact(SOCKET sock, void* buf, int len) {
    char* p = static_cast<char*>(buf);
    int got = 0;
    while (got < len) {
        int n = recv(sock, p + got, len - got, 0);
        if (n <= 0) return false;  // closed or error
        got += n;
    }
    return true;
}

bool send_all(SOCKET sock, const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

} // namespace

/**
 * Executes a SOCKS5 handshake.
 *   Greeting -> [Username/Password sub-negotiation] -> CONNECT request.
 * When credentials are supplied we offer both NO-AUTH (0x00) and
 * USERNAME/PASSWORD (0x02) and follow whichever method the proxy selects; with
 * no credentials we offer NO-AUTH only.
 */
bool proxy_handshake(SOCKET sock, const std::string& target_host, uint16_t target_port,
                     const std::string& user, const std::string& pass) {

    const bool have_creds = !user.empty() || !pass.empty();

    if (user.size() > 255 || pass.size() > 255 || target_host.size() > 255) {
        std::cerr << "[SOCKS5] Error: username/password/host exceeds 255 bytes.\n";
        return false;
    }

    // --- 1. Greeting: advertise the auth methods we support ---
    std::vector<unsigned char> greeting = {0x05};
    if (have_creds) {
        greeting.push_back(0x02);              // 2 methods
        greeting.push_back(0x00);              //   no-auth
        greeting.push_back(0x02);              //   username/password
    } else {
        greeting.push_back(0x01);              // 1 method
        greeting.push_back(0x00);              //   no-auth
    }
    if (!send_all(sock, (const char*)greeting.data(), (int)greeting.size())) return false;

    unsigned char method_resp[2];
    if (!recv_exact(sock, method_resp, 2)) return false;
    if (method_resp[0] != 0x05) {
        std::cerr << "[SOCKS5] Error: not a SOCKS5 proxy.\n";
        return false;
    }

    const unsigned char chosen = method_resp[1];
    if (chosen == 0xFF) {
        std::cerr << "[SOCKS5] Error: proxy rejected all offered auth methods.\n";
        return false;
    }

    // --- 2. Username/Password sub-negotiation (only if the proxy chose 0x02) ---
    if (chosen == 0x02) {
        if (!have_creds) {
            std::cerr << "[SOCKS5] Error: proxy requires credentials but none given.\n";
            return false;
        }
        std::string auth_pkt;
        auth_pkt.push_back(0x01);                               // sub-version
        auth_pkt.push_back((unsigned char)user.length());
        auth_pkt += user;
        auth_pkt.push_back((unsigned char)pass.length());
        auth_pkt += pass;

        if (!send_all(sock, auth_pkt.data(), (int)auth_pkt.size())) return false;

        unsigned char auth_resp[2];
        if (!recv_exact(sock, auth_resp, 2)) return false;
        if (auth_resp[1] != 0x00) {
            std::cerr << "[SOCKS5] Error: Authentication failed. Check credentials.\n";
            return false;
        }
    } else if (chosen != 0x00) {
        std::cerr << "[SOCKS5] Error: proxy selected unsupported auth method "
                  << (int)chosen << ".\n";
        return false;
    }

    // --- 3. Connection Request ---
    // [Ver 5, Cmd 1 (Connect), Rsv 0x00, ATYP 0x03 (Domain)]
    std::vector<unsigned char> req = {0x05, 0x01, 0x00, 0x03};
    req.push_back((unsigned char)target_host.length());
    req.insert(req.end(), target_host.begin(), target_host.end());

    uint16_t net_port = htons(target_port);
    unsigned char* p_port = (unsigned char*)&net_port;
    req.push_back(p_port[0]);
    req.push_back(p_port[1]);

    if (!send_all(sock, (const char*)req.data(), (int)req.size())) return false;

    // --- 4. Precise consumption of the response so TLS starts on a clean buffer.
    // Read first 4 bytes: [VER, REP, RSV, ATYP]
    unsigned char resp_hdr[4];
    if (!recv_exact(sock, resp_hdr, 4)) return false;

    if (resp_hdr[1] != 0x00) {
        std::cerr << "[SOCKS5] Connection refused by proxy. Code: " << (int)resp_hdr[1] << "\n";
        return false;
    }

    // Consume the "BND.ADDR" + "BND.PORT" fields based on ATYP.
    if (resp_hdr[3] == 0x01) {              // IPv4: 4 + 2
        char junk[6];
        if (!recv_exact(sock, junk, 6)) return false;
    } else if (resp_hdr[3] == 0x03) {      // Domain: 1 len + N + 2
        unsigned char domain_len;
        if (!recv_exact(sock, &domain_len, 1)) return false;
        std::vector<char> junk(domain_len + 2);
        if (!recv_exact(sock, junk.data(), (int)junk.size())) return false;
    } else if (resp_hdr[3] == 0x04) {      // IPv6: 16 + 2
        char junk[18];
        if (!recv_exact(sock, junk, 18)) return false;
    } else {
        std::cerr << "[SOCKS5] Error: unknown ATYP " << (int)resp_hdr[3] << " in reply.\n";
        return false;
    }

    // Buffer is now clean. Ready for BoringSSL/TLS.
    return true;
}
