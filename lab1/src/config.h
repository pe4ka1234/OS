#pragma once
#include "common.h"

static std::string trim(std::string s) {
    auto issp = [](unsigned char c){ return std::isspace(c); };
    while (!s.empty() && issp((unsigned char)s.front()))
        s.erase(s.begin());
    while (!s.empty() && issp((unsigned char)s.back()))
        s.pop_back();
    return s;
}

static bool iequals(std::string a, std::string b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (std::tolower(ca) != std::tolower(cb))
            return false;
    }
    return true;
}

static std::optional<std::uintmax_t> parse_size_to_bytes(std::string token) {
    token = trim(token);
    if (token.empty())
        return std::nullopt;

    char suffix = '\0';
    if (!std::isdigit((unsigned char)token.back())) {
        suffix = (char)std::toupper((unsigned char)token.back());
        token.pop_back();
        token = trim(token);
    }

    char* end = nullptr;
    errno = 0;
    unsigned long long val = std::strtoull(token.c_str(), &end, 10);
    if (errno != 0 || end == token.c_str() || *end != '\0')
        return std::nullopt;

    unsigned long long mult = 1ULL;
    switch (suffix) {
        case '\0':
        case 'B': mult = 1ULL; break;
        case 'K': mult = 1024ULL; break;
        case 'M': mult = 1024ULL * 1024ULL; break;
        case 'G': mult = 1024ULL * 1024ULL * 1024ULL; break;
        default: return std::nullopt;
    }

    if (val > std::numeric_limits<unsigned long long>::max() / mult)
        return std::nullopt;
    return static_cast<std::uintmax_t>(val * mult);
}

static std::optional<int> parse_duration_seconds(std::string token) {
    token = trim(token);
    if (token.empty())
        return std::nullopt;

    char suffix = '\0';
    if (!std::isdigit((unsigned char)token.back())) {
        suffix = (char)std::tolower((unsigned char)token.back());
        token.pop_back();
        token = trim(token);
    }

    char* end = nullptr;
    errno = 0;
    long long val = std::strtoll(token.c_str(), &end, 10);
    if (errno != 0 || end == token.c_str() || *end != '\0' || val < 0)
        return std::nullopt;

    long long mult = 1LL;
    switch (suffix) {
        case '\0':
        case 's': mult = 1LL; break;
        case 'm': mult = 60LL; break;
        case 'h': mult = 60LL * 60LL; break;
        default: return std::nullopt;
    }

    long long total = val * mult;
    if (total > std::numeric_limits<int>::max())
        return std::nullopt;
    
    return static_cast<int>(total);
}

static std::vector<Rule> load_config_lines(const fs::path& conf_path) {
    std::vector<Rule> rules;

    std::ifstream in(conf_path);
    if (!in) {
        syslog(LOG_ERR, "cannot open config: %s", conf_path.c_str());
        return rules;
    }

    fs::path base_dir = conf_path.parent_path();
    int new_interval = -1;

    std::string raw;
    size_t lineno = 0;
    while (std::getline(in, raw)) {
        ++lineno;
        raw = trim(raw);
        if (raw.empty() || raw[0] == '#')
            continue;

        if (raw.rfind("interval", 0) == 0 || raw.rfind("INTERVAL", 0) == 0) {
            std::string key, val;
            {
                std::istringstream iss(raw);
                iss >> key;
                if (!(iss >> val)) {
                    syslog(LOG_WARNING, "config %s:%zu: missing interval value", conf_path.c_str(), lineno);
                    continue;
                }
            }

            if (iequals(key, "interval")) {
                auto sec = parse_duration_seconds(val);
                if (!sec) {
                    syslog(LOG_WARNING, "config %s:%zu: bad interval '%s'", conf_path.c_str(), lineno, val.c_str());
                    continue;
                }
                new_interval = *sec;
                syslog(LOG_INFO, "config: interval set to %d second(s)", new_interval);
            }
            continue;
        }

        std::string folder, size_s;
        {
            std::istringstream iss(raw);
            if (!(iss >> folder)) {
                syslog(LOG_WARNING, "config %s:%zu: missing folder", conf_path.c_str(), lineno);
                continue;
            }
            if (!(iss >> size_s)) {
                syslog(LOG_WARNING, "config %s:%zu: missing size", conf_path.c_str(), lineno);
                continue;
            }
        }

        auto size_bytes = parse_size_to_bytes(size_s);
        if (!size_bytes) {
            syslog(LOG_WARNING, "config %s:%zu: bad size '%s'", conf_path.c_str(), lineno, size_s.c_str());
            continue;
        }

        fs::path folder_path(folder);
        if (folder_path.is_relative()) {
            folder_path = base_dir / folder_path;
        }

        std::error_code ec;
        fs::path canon = fs::weakly_canonical(folder_path, ec);
        if (ec) {
            fs::path joined = base_dir / folder_path;
            canon = fs::weakly_canonical(joined, ec);
            folder_path = ec ? fs::absolute(joined) : canon;
        } else {
            folder_path = canon;
        }

        rules.push_back(Rule{folder_path, *size_bytes});
    }

    if (new_interval > 0)
        g_interval_sec.store(new_interval);
    syslog(LOG_INFO, "config loaded: %zu rule(s), interval=%d second(s), base='%s'", rules.size(), g_interval_sec.load(), base_dir.c_str());

    return rules;
}
