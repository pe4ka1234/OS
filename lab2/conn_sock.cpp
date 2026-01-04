#include "conn_iface.h"
#include "io_timeout.h"
#include <sys/socket.h>
#include <unistd.h>

static constexpr const char* kType = "sock";

class SockConn final : public IConn {
public:
    explicit SockConn(int fd) : fd_(fd) {}
    ~SockConn() override {
        if (fd_ >= 0) ::close(fd_);
    }
    bool Read(void* buf, std::size_t count) override {
        return read_exact_timeout(fd_, buf, count, kDefaultTimeoutMs);
    }
    bool Write(const void* buf, std::size_t count) override {
        return write_all_timeout(fd_, buf, count, kDefaultTimeoutMs);
    }
private:
    int fd_;
};

ConnPair create_conn_pair(int client_id, int /*host_pid*/) {
    int sv[2]{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return {};
    }

    ConnPair pair;
    pair.host.spec.client_id = client_id;
    pair.host.spec.is_host = true;
    pair.host.spec.fd_read = sv[0];
    pair.host.spec.fd_write = sv[0];
    pair.host.close_fds = { sv[1] };

    pair.child.spec.client_id = client_id;
    pair.child.spec.is_host = false;
    pair.child.spec.fd_read = sv[1];
    pair.child.spec.fd_write = sv[1];
    pair.child.close_fds = { sv[0] };

    return pair;
}

std::unique_ptr<IConn> make_conn(const ConnSpec& spec) {
    if (spec.fd_read < 0) return nullptr;
    return std::make_unique<SockConn>(spec.fd_read);
}

void cleanup_host_resources(int /*host_pid*/, int /*n_clients*/) {
    // nothing
}

const char* conn_type_code() { return kType; }
