#pragma once
#include "common.h"

static std::uintmax_t dir_size_recursive(const fs::path& p) {
    std::error_code ec;
    std::uintmax_t total = 0;

    if (!fs::exists(p, ec) || !fs::is_directory(p, ec))
        return 0;

    for (fs::recursive_directory_iterator it(p, fs::directory_options::skip_permission_denied, ec), end; it != end; ++it) {
        if (ec) {
            syslog(LOG_WARNING, "dir_size: error accessing '%s': %s", it->path().c_str(), ec.message().c_str());
            continue;
        }
        const auto& entry = *it;
        std::error_code fec;
        if (entry.is_regular_file(fec)) {
            std::uintmax_t sz = fs::file_size(entry.path(), fec);
            if (!fec) total += sz;
        }
    }
    return total;
}

static void remove_contents_of(const fs::path& folder) {
    std::error_code ec;
    if (!fs::exists(folder, ec) || !fs::is_directory(folder, ec))
        return;

    for (auto& entry : fs::directory_iterator(folder, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) break;
        std::error_code rec;
        fs::remove_all(entry.path(), rec);
        if (rec) {
            syslog(LOG_WARNING, "remove: cannot remove '%s': %s", entry.path().c_str(), rec.message().c_str());
        }
    }
}
