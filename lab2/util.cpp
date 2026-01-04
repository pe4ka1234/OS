#include "util.h"
#include <cerrno>
#include <climits>
#include <cstdlib>

bool parse_int(const std::string& s, int& out) {
    errno = 0;
    char* end = nullptr;
    long v = std::strtol(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0') return false;
    if (v < INT_MIN || v > INT_MAX) return false;
    out = static_cast<int>(v);
    return true;
}

int clamp_int(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int abs_int(int x) { return x < 0 ? -x : x; }
