#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct ConnSpec {
    int client_id = 0;
    bool is_host = false;

    // For fd-based transports (pipe/sock)
    int fd_read = -1;
    int fd_write = -1;

    // For name-based transports (fifo)
    std::string name_a; // e.g. host->client path
    std::string name_b; // e.g. client->host path
};

struct ConnSide {
    ConnSpec spec;
    std::vector<int> close_fds; // fds to close in this process after fork
};

struct ConnPair {
    ConnSide host;
    ConnSide child;
};

class IConn {
public:
    virtual ~IConn() = default;
    virtual bool Read(void* buf, std::size_t count) = 0;          // uses 5s timeout internally
    virtual bool Write(const void* buf, std::size_t count) = 0;   // uses 5s timeout internally
};

// Implemented in each conn_*.cpp (exactly one is linked into each host_* binary)
ConnPair create_conn_pair(int client_id, int host_pid);
std::unique_ptr<IConn> make_conn(const ConnSpec& spec);
void cleanup_host_resources(int host_pid, int n_clients);
const char* conn_type_code();
