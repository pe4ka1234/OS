#include <csignal>
#include <cstring>
#include <cstdlib>
#include <cerrno>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <limits>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

namespace fs = std::filesystem;

static const char* DEFAULT_CONF_NAME = "lab1.conf";
static const char* PIDFILE_PATH = "/tmp/lab1d.pid";
// по умолчанию 30 c
static std::atomic<int> g_interval_sec{30};

struct Rule {
    fs::path folder;
    std::uintmax_t threshold_bytes{};
};

static std::atomic<bool> g_reload{false};
static std::atomic<bool> g_terminate{false};

static void signal_handler(int sig) {
    if (sig == SIGHUP)
        g_reload.store(true);
    if (sig == SIGTERM)
        g_terminate.store(true);
}

static std::optional<pid_t> read_pidfile(const char* path) {
    std::ifstream in(path);
    if (!in)
        return std::nullopt;
    pid_t pid{};
    in >> pid;
    if (!in)
        return std::nullopt;
    return pid;
}

static bool write_pidfile(const char* path, pid_t pid) {
    std::ofstream out(path, std::ios::trunc);
    if (!out)
        return false;
    out << pid << "\n";
    return static_cast<bool>(out);
}

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
    for (size_t i=0;i<a.size();++i) {
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i]))
            return false;
    }
    return true;
}

// "30B", "30K", "5m", "2G"
static std::optional<std::uintmax_t> parse_size_to_bytes(std::string token) {
    token = trim(token);
    if (token.empty())
        return std::nullopt;

    for (auto &c : token)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    char suffix = '\0';
    if (!token.empty() && !std::isdigit((unsigned char)token.back())) {
        suffix = token.back();
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

// "30", "30s", "5m", "2h"
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

    long long mult = 1;
    switch (suffix) {
        case '\0':
        case 's': mult = 1; break;
        case 'm': mult = 60; break;
        case 'h': mult = 3600;break;
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
    if (base_dir.empty())
        base_dir = fs::current_path();

    std::string line;
    size_t lineno = 0;
    int new_interval = -1;

    while (std::getline(in, line)) {
        ++lineno;
        std::string raw = trim(line);
        if (raw.empty() || raw[0] == '#')
            continue;

        {
            std::istringstream iss(raw);
            std::string key; iss >> key;
            if (iequals(key, "interval")) {
                std::string val;
                if (!(iss >> val)) {
                    syslog(LOG_WARNING, "config %s:%zu: missing interval value", conf_path.c_str(), lineno);
                    continue;
                }
                auto sec = parse_duration_seconds(val);
                if (!sec || *sec <= 0) {
                    syslog(LOG_WARNING, "config %s:%zu: bad interval '%s'", conf_path.c_str(), lineno, val.c_str());
                } else {
                    new_interval = *sec;
                    syslog(LOG_INFO, "config: interval set to %d second(s)", new_interval);
                }
                continue;
            }
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

        fs::path folder_path = fs::path(folder);
        if (folder_path.is_relative()) {
            fs::path joined = base_dir / folder_path;
            std::error_code ec;
            fs::path canon = fs::weakly_canonical(joined, ec);
            folder_path = ec ? fs::absolute(joined) : canon;
        } else {
            std::error_code ec;
            fs::path canon = fs::weakly_canonical(folder_path, ec);
            folder_path = ec ? folder_path : canon;
        }


        rules.push_back(Rule{folder_path, *size_bytes});
    }

    if (new_interval > 0)
        g_interval_sec.store(new_interval);
    syslog(LOG_INFO, "config loaded: %zu rule(s), interval=%d s, base_dir='%s'", rules.size(), g_interval_sec.load(), base_dir.c_str());
    return rules;
}


static std::uintmax_t dir_size_recursive(const fs::path& p) {
    std::uintmax_t total = 0;
    std::error_code ec;
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

    for (fs::directory_iterator it(folder, fs::directory_options::skip_permission_denied, ec), end; it != end; ++it) {
        std::error_code rec;
        const fs::path& child = it->path();
        fs::remove_all(child, rec);
        if (rec) {
            syslog(LOG_WARNING, "remove: failed to remove '%s': %s", child.c_str(), rec.message().c_str());
        } else {
            syslog(LOG_INFO, "removed '%s'", child.c_str());
        }
    }
}

class DaemonApp {
public:
    static DaemonApp& instance() {
        static DaemonApp inst;
        return inst;
    }

    void set_initial_config_path(fs::path p) {
        std::error_code ec;
        conf_path_ = fs::absolute(p, ec);
        if (ec) conf_path_ = p;
    }
    
    void run() {
        rules_ = load_config_lines(conf_path_);

        while (!g_terminate.load()) {
            if (g_reload.load()) {
                g_reload.store(false);
                syslog(LOG_INFO, "SIGHUP received: reloading config");
                rules_ = load_config_lines(conf_path_);
            }

            execute_once();

            int sleep_total = g_interval_sec.load();
            if (sleep_total < 1) sleep_total = 1;
            for (int i = 0; i < sleep_total && !g_terminate.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (g_reload.load()) break;
            }
        }

        syslog(LOG_INFO, "SIGTERM received: exiting");
    }

    DaemonApp(const DaemonApp&) = delete;
    DaemonApp& operator=(const DaemonApp&) = delete;
    DaemonApp(DaemonApp&&) = delete;
    DaemonApp& operator=(DaemonApp&&) = delete;

    static void* operator new(std::size_t) = delete;
    static void  operator delete(void*) = delete;

private:
    DaemonApp() = default;
    ~DaemonApp() = default;

    void execute_once() {
        for (const auto& rule : rules_) {
            const fs::path& folder = rule.folder;
            const auto limit = rule.threshold_bytes;

            std::error_code ec;
            if (!fs::exists(folder, ec) || !fs::is_directory(folder, ec)) {
                syslog(LOG_WARNING, "folder '%s' does not exist or not a directory", folder.c_str());
                continue;
            }

            const std::uintmax_t sz = dir_size_recursive(folder);
            syslog(LOG_INFO, "folder '%s' total size = %ju bytes (limit = %ju)",
                   folder.c_str(),
                   static_cast<uintmax_t>(sz),
                   static_cast<uintmax_t>(limit));

            if (sz > limit) {
                syslog(LOG_NOTICE, "limit exceeded for '%s' -> removing contents", folder.c_str());
                remove_contents_of(folder);
            }
        }
    }

    std::filesystem::path conf_path_;
    std::vector<Rule> rules_;
};

static void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        std::exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        std::perror("setsid");
        std::exit(EXIT_FAILURE);
    }

    std::signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        std::perror("fork2");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        std::exit(EXIT_SUCCESS);
    }

    umask(0);
    if (chdir("/") < 0) {
        std::perror("chdir");
        std::exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int fd0 = open("/dev/null", O_RDWR);
    int fd1 = dup(fd0);
    int fd2 = dup(fd0);
    (void)fd0; (void)fd1; (void)fd2;
}

static void ensure_singleton_with_pidfile() {
    auto old = read_pidfile(PIDFILE_PATH);
    if (!old.has_value())
        return;

    const pid_t pid = *old;
    if (pid <= 1) {
        unlink(PIDFILE_PATH);
        return;
    }

    fs::path proc_dir = fs::path("/proc") / std::to_string(pid);
    if (!fs::exists(proc_dir)) {
        unlink(PIDFILE_PATH);
        return;
    }

    if (kill(pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            unlink(PIDFILE_PATH);
            return;
        }
        if (errno == EPERM) {
            syslog(LOG_ERR, "another instance is running (pid=%d), but no permission to signal it; exiting", (int)pid);
            std::exit(EXIT_FAILURE);
        }
        syslog(LOG_ERR, "failed to send SIGTERM to pid=%d: %s; exiting", (int)pid, std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }

    // ждем до ~5s
    for (int i = 0; i < 50; ++i) {
        if (!fs::exists(proc_dir)) {
            unlink(PIDFILE_PATH);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    syslog(LOG_WARNING, "previous instance (pid=%d) did not terminate in time; exiting to avoid multiple instances", (int)pid);
    std::exit(EXIT_FAILURE);
}


int main(int argc, char* argv[]) {
    openlog("lab1d", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    fs::path conf_path = (argc >= 2) ? fs::path(argv[1]) : fs::path(DEFAULT_CONF_NAME);
    DaemonApp::instance().set_initial_config_path(conf_path);

    ensure_singleton_with_pidfile();
    daemonize();

    pid_t self = getpid();
    if (!write_pidfile(PIDFILE_PATH, self)) {
        syslog(LOG_ERR, "cannot write pidfile: %s", PIDFILE_PATH);
    }

    std::signal(SIGHUP,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    syslog(LOG_INFO, "daemon started (pid=%d), config='%s'", (int)self, conf_path.c_str());
    DaemonApp::instance().run();

    syslog(LOG_INFO, "daemon stopped");
    closelog();

    return 0;
}