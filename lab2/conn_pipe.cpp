#include "conn_iface.h"
#include "io_timeout.h"
#include <cerrno>
#include <cstring>
#include <unistd.h>

static constexpr const char* kType = "pipe";

class PipeConn final : public IConn {
public:
    explicit PipeConn(const ConnSpec& s) : rfd_(s.fd_read), wfd_(s.fd_write) {}
    ~PipeConn() override {
        if (rfd_ >= 0) ::close(rfd_);
        if (wfd_ >= 0 && wfd_ != rfd_) ::close(wfd_);
    }
    bool Read(void* buf, std::size_t count) override {
        return read_exact_timeout(rfd_, buf, count, kDefaultTimeoutMs);
    }
    bool Write(const void* buf, std::size_t count) override {
        return write_all_timeout(wfd_, buf, count, kDefaultTimeoutMs);
    }
private:
    int rfd_;
    int wfd_;
};

ConnPair create_conn_pair(int client_id, int /*host_pid*/) {
    int p2c[2]{-1,-1};
    int c2p[2]{-1,-1};
    if (::pipe(p2c) != 0) {
        // best-effort: leave fds=-1; host will fail later
        return {};
    }
    if (::pipe(c2p) != 0) {
        ::close(p2c[0]); ::close(p2c[1]);
        return {};
    }

    ConnPair pair;
    // parent(host): read from c2p[0], write to p2c[1]
    pair.host.spec.client_id = client_id;
    pair.host.spec.is_host = true;
    pair.host.spec.fd_read = c2p[0];
    pair.host.spec.fd_write = p2c[1];
    pair.host.close_fds = { p2c[0], c2p[1] };

    // child: read from p2c[0], write to c2p[1]
    pair.child.spec.client_id = client_id;
    pair.child.spec.is_host = false;
    pair.child.spec.fd_read = p2c[0];
    pair.child.spec.fd_write = c2p[1];
    pair.child.close_fds = { p2c[1], c2p[0] };

    return pair;
}

std::unique_ptr<IConn> make_conn(const ConnSpec& spec) {
    if (spec.fd_read < 0 || spec.fd_write < 0) return nullptr;
    return std::make_unique<PipeConn>(spec);
}

void cleanup_host_resources(int /*host_pid*/, int /*n_clients*/) {
    // nothing
}

const char* conn_type_code() { return kType; }
