#pragma once

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
#include <cctype>
#include <sstream>

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
    if (sig == SIGHUP)  g_reload.store(true);
    if (sig == SIGTERM) g_terminate.store(true);
}
