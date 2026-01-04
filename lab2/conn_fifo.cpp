#include "conn_iface.h"
#include "io_timeout.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static constexpr const char* kType = "fifo";

// Helper: open with timeout for O_WRONLY|O_NONBLOCK (fails with ENXIO until reader opens).
static int open_wronly_timeout(const std::string& path, int timeout_ms) {
    const int step_ms = 50;
    int waited = 0;
    while (waited < timeout_ms) {
        const int fd = ::open(path.c_str(), O_WRONLY | O_NONBLOCK);
        if (fd >= 0) return fd;
        if (errno != ENXIO && errno != ENOENT && errno != EINTR) return -1;
        ::usleep(step_ms * 1000);
        waited += step_ms;
    }
    return -1;
}

class FifoConn final : public IConn {
public:
    explicit FifoConn(const ConnSpec& s) : is_host_(s.is_host), a_(s.name_a), b_(s.name_b) {
        // We use TWO FIFOs per client: a_ is host->client, b_ is client->host.
        // Open read ends first nonblocking to avoid deadlocks.
        if (is_host_) {
            // host reads from b_, writes to a_
            rfd_ = ::open(b_.c_str(), O_RDONLY | O_NONBLOCK);
            wfd_ = open_wronly_timeout(a_, kDefaultTimeoutMs);
        } else {
            // client reads from a_, writes to b_
            rfd_ = ::open(a_.c_str(), O_RDONLY | O_NONBLOCK);
            wfd_ = open_wronly_timeout(b_, kDefaultTimeoutMs);
        }

        // If open failed, keep fds=-1; host/client will detect failure later via Read/Write.
    }

    ~FifoConn() override {
        if (rfd_ >= 0) ::close(rfd_);
        if (wfd_ >= 0) ::close(wfd_);
    }

    bool Read(void* buf, std::size_t count) override {
        if (rfd_ < 0) return false;
        return read_exact_timeout(rfd_, buf, count, kDefaultTimeoutMs);
    }

    bool Write(const void* buf, std::size_t count) override {
        if (wfd_ < 0) return false;
        return write_all_timeout(wfd_, buf, count, kDefaultTimeoutMs);
    }

private:
    bool is_host_;
    std::string a_;
    std::string b_;
    int rfd_ = -1;
    int wfd_ = -1;
};

static std::string fifo_path(int host_pid, int client_id, const char* suffix) {
    return "/tmp/lab2_" + std::to_string(host_pid) + "_client" + std::to_string(client_id) + "_" + suffix;
}

ConnPair create_conn_pair(int client_id, int host_pid) {
    ConnPair pair;
    const std::string h2c = fifo_path(host_pid, client_id, "h2c.fifo");
    const std::string c2h = fifo_path(host_pid, client_id, "c2h.fifo");

    // Host creates FIFO files (0600). If already exists - unlink and recreate.
    ::unlink(h2c.c_str());
    ::unlink(c2h.c_str());
    (void)::mkfifo(h2c.c_str(), 0600);
    (void)::mkfifo(c2h.c_str(), 0600);

    pair.host.spec.client_id = client_id;
    pair.host.spec.is_host = true;
    pair.host.spec.name_a = h2c;
    pair.host.spec.name_b = c2h;

    pair.child.spec.client_id = client_id;
    pair.child.spec.is_host = false;
    pair.child.spec.name_a = h2c;
    pair.child.spec.name_b = c2h;

    return pair;
}

std::unique_ptr<IConn> make_conn(const ConnSpec& spec) {
    if (spec.name_a.empty() || spec.name_b.empty()) return nullptr;
    return std::make_unique<FifoConn>(spec);
}

void cleanup_host_resources(int host_pid, int n_clients) {
    // Parent removes fifo files after completion (requirement).
    for (int i = 1; i <= n_clients; i++) {
        const std::string h2c = fifo_path(host_pid, i, "h2c.fifo");
        const std::string c2h = fifo_path(host_pid, i, "c2h.fifo");
        ::unlink(h2c.c_str());
        ::unlink(c2h.c_str());
    }
}

const char* conn_type_code() { return kType; }
