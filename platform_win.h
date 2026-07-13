#pragma once

// ---------------------------------------------------------------------------
// Cross-platform networking shim.
//
// Historically this header was Windows-only (hence the name). It now provides a
// single Winsock-compatible surface so the rest of the codebase can be written
// once and compile on both Windows (Winsock2) and POSIX (Berkeley sockets).
// The filename is kept to avoid churning every include site.
// ---------------------------------------------------------------------------

#ifdef _WIN32

// --- Windows base ---
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// --- POSIX compatibility for MSVC ---
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;

// --- Sanitize Windows macro pollution ---
#undef min
#undef max
#undef interface
#undef byte

#else // ----------------------------- POSIX -----------------------------------

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstdint>

// Winsock-compatible aliases so call sites stay identical across platforms.
typedef int SOCKET;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int    SOCKET_ERROR   = -1;
typedef unsigned long u_long;

inline int closesocket(SOCKET s) { return ::close(s); }

#endif // _WIN32

// ---------------------------------------------------------------------------
// Set a socket to blocking / non-blocking mode (replaces direct ioctlsocket /
// fcntl calls so the HTTP/2 event loop toggling is portable). Returns 0 on
// success, non-zero on failure.
// ---------------------------------------------------------------------------
inline int set_socket_nonblocking(SOCKET sock, bool nonblocking) {
#ifdef _WIN32
    u_long mode = nonblocking ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nonblocking) flags |= O_NONBLOCK;
    else             flags &= ~O_NONBLOCK;
    return fcntl(sock, F_SETFL, flags);
#endif
}

// ---------------------------------------------------------------------------
// Block until a socket is readable (or timeout_ms elapses). Lets the HTTP/2
// event loop sleep on the socket instead of busy-polling with a fixed delay.
// Returns >0 if readable, 0 on timeout, <0 on error.
// ---------------------------------------------------------------------------
inline int wait_readable(SOCKET sock, int timeout_ms) {
#ifdef _WIN32
    WSAPOLLFD pfd;
    pfd.fd = sock;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;
    return WSAPoll(&pfd, 1, timeout_ms);
#else
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;
    return ::poll(&pfd, 1, timeout_ms);
#endif
}
