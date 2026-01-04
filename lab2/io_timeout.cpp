#include "io_timeout.h"
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <unistd.h>

static bool wait_fd(int fd, short events, int timeout_ms) {
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = events;
    for (;;) {
        const int rc = ::poll(&pfd, 1, timeout_ms);
        if (rc > 0) return true;
        if (rc == 0) return false; // timeout
        if (errno == EINTR) continue;
        return false;
    }
}

bool read_exact_timeout(int fd, void* buf, std::size_t n, int timeout_ms) {
    auto* p = static_cast<unsigned char*>(buf);
    std::size_t got = 0;
    while (got < n) {
        if (!wait_fd(fd, POLLIN, timeout_ms)) return false;
        const ssize_t rc = ::read(fd, p + got, n - got);
        if (rc > 0) {
            got += static_cast<std::size_t>(rc);
            continue;
        }
        if (rc == 0) return false; // EOF
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return false;
    }
    return true;
}

bool write_all_timeout(int fd, const void* buf, std::size_t n, int timeout_ms) {
    const auto* p = static_cast<const unsigned char*>(buf);
    std::size_t sent = 0;
    while (sent < n) {
        if (!wait_fd(fd, POLLOUT, timeout_ms)) return false;
        const ssize_t rc = ::write(fd, p + sent, n - sent);
        if (rc > 0) {
            sent += static_cast<std::size_t>(rc);
            continue;
        }
        if (rc == 0) return false;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return false;
    }
    return true;
}
