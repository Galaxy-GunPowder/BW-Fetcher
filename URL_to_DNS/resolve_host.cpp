#include "resolve_host.h"

#include <thread>
#include <future>
#include <chrono>
#include <stdexcept>
#include <cstring>
#include <memory>

// NB: default arguments live in resolve_host.h, so they must NOT be repeated on
// these definitions (the header is now included above).

// Existing DNS lookup
ResolvedHost dns_lookup_host(const std::string& host, const std::string& port) {
    ResolvedHost res;
    struct addrinfo hints = {0}, *info;
    hints.ai_family = AF_UNSPEC;        // IPv4 + IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &info) != 0) {
        throw std::runtime_error("DNS resolution failed for: " + host);
    }

    for (struct addrinfo* p = info; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            res.ip4.push_back(*(struct sockaddr_in*)p->ai_addr);
        } else if (p->ai_family == AF_INET6) {
            res.ip6.push_back(*(struct sockaddr_in6*)p->ai_addr);
        }
    }

    freeaddrinfo(info);
    return res;
}

// Try connecting to a single IP. Uses a NON-BLOCKING connect + select so the
// timeout is actually honored (SO_RCVTIMEO/SO_SNDTIMEO do NOT apply to connect)
// and disables Nagle so the TLS ClientHello / HTTP/2 preface go out immediately.
std::optional<TcpEndpoint> try_connect(sockaddr* sa, socklen_t sa_len, int timeout_ms) {
    SOCKET sockfd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) return std::nullopt;

    // Disable Nagle: small latency-critical writes (ClientHello, SETTINGS+HEADERS)
    // should not wait to be coalesced.
    int one = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));

    set_socket_nonblocking(sockfd, true);

    bool connected = (connect(sockfd, sa, sa_len) == 0);
    if (!connected) {
#ifdef _WIN32
        bool in_progress = (WSAGetLastError() == WSAEWOULDBLOCK);
#else
        bool in_progress = (errno == EINPROGRESS);
#endif
        if (in_progress) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(sockfd, &wset);
            struct timeval tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select((int)sockfd + 1, nullptr, &wset, nullptr, &tv) > 0) {
                int soerr = 0;
                socklen_t len = sizeof(soerr);
                getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len);
                connected = (soerr == 0);
            }
        }
    }

    if (!connected) {
        closesocket(sockfd);
        return std::nullopt;
    }

    set_socket_nonblocking(sockfd, false); // blocking again for the TLS handshake
    TcpEndpoint ep;
    ep.sock = sockfd;
    memcpy(&ep.addr, sa, sa_len);
    ep.addr_len = sa_len;
    return ep;
}

// Happy Eyeballs style connect.
//
// Races every candidate address (IPv6 + IPv4) CONCURRENTLY and returns the
// first socket that connects. The previous implementation slept a fixed
// `ipv4_delay_ms` (250ms) before even starting IPv4 attempts, which became dead
// time on every fetch whenever IPv6 was unreachable. We now launch both families
// at once; IPv6 is still preferred because its attempts are polled first.
//
// As soon as a winner is found we hand any still-pending attempts to a detached
// thread that drains them and closes any redundant sockets, so a slow/hung
// address never delays returning the working connection.
TcpEndpoint happy_eyeballs_connect(const ResolvedHost& host_res, int /*ipv4_delay_ms*/) {
    auto futures = std::make_shared<std::vector<std::future<std::optional<TcpEndpoint>>>>();

    for (const auto& ip6 : host_res.ip6) {
        futures->push_back(std::async(std::launch::async, [ip6]() {
            sockaddr_in6 a = ip6;
            return try_connect((sockaddr*)&a, sizeof(a));
        }));
    }
    for (const auto& ip4 : host_res.ip4) {
        futures->push_back(std::async(std::launch::async, [ip4]() {
            sockaddr_in a = ip4;
            return try_connect((sockaddr*)&a, sizeof(a));
        }));
    }

    const size_t n = futures->size();
    std::vector<bool> done(n, false);
    size_t completed = 0;
    std::optional<TcpEndpoint> winner;

    // Poll for the first success without blocking on a slow earlier attempt.
    while (completed < n && !winner) {
        for (size_t i = 0; i < n && !winner; ++i) {
            if (done[i]) continue;
            if ((*futures)[i].wait_for(std::chrono::milliseconds(2)) ==
                std::future_status::ready) {
                done[i] = true;
                ++completed;
                if (auto ep = (*futures)[i].get()) winner = ep; // first success wins
            }
        }
    }

    // Drain any attempts still in flight on a detached thread (closes redundant
    // sockets) so the caller gets the winner immediately.
    if (completed < n) {
        std::thread([futures, done]() mutable {
            for (size_t i = 0; i < futures->size(); ++i) {
                if (done[i] || !(*futures)[i].valid()) continue;
                if (auto ep = (*futures)[i].get()) closesocket(ep->sock);
            }
        }).detach();
    }

    if (winner) return *winner;
    throw std::runtime_error("No IP could be connected (both IPv6 and IPv4 failed)");
}
