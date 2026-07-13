#pragma once
#include "../platform_win.h"
#include <string>
#include <vector>
#include <optional>

struct ResolvedHost {
    std::vector<sockaddr_in> ip4;
    std::vector<sockaddr_in6> ip6;
};

struct TcpEndpoint {
    SOCKET sock;                // connected socket (SOCKET, not int: a Win64
                                // socket handle does not fit in an int)
    sockaddr_storage addr;
    socklen_t addr_len;
};

// DNS lookup
ResolvedHost dns_lookup_host(const std::string& host, const std::string& port = "443");

// Happy Eyeballs connect
TcpEndpoint happy_eyeballs_connect(const ResolvedHost& host_res, int ipv4_delay_ms = 250);

// Try connecting to a single IP
std::optional<TcpEndpoint> try_connect(sockaddr* sa, socklen_t sa_len, int timeout_ms = 3000);
