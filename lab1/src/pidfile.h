#pragma once
#include "common.h"

static std::optional<pid_t> read_pidfile(const char* path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;

    long long pid_ll = -1;
    in >> pid_ll;
    if (!in || pid_ll <= 0) return std::nullopt;
    return static_cast<pid_t>(pid_ll);
}

static bool write_pidfile(const char* path, pid_t pid) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    out << pid << "\n";
    return (bool)out;
}
