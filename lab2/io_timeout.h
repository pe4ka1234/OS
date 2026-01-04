#pragma once
#include <cstddef>

// Returns true on success, false on timeout/error.
bool read_exact_timeout(int fd, void* buf, std::size_t n, int timeout_ms);
bool write_all_timeout(int fd, const void* buf, std::size_t n, int timeout_ms);

// Defaults used by this lab for all blocking waits (5 seconds) per assignment.
static constexpr int kDefaultTimeoutMs = 5000;
