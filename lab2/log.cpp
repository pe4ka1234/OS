#include "log.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unistd.h>

static const char* lvl_str(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
    }
    return "INFO";
}

void log_msg(LogLevel lvl, const std::string& who, const std::string& msg) {
    std::ostream& os = (lvl == LogLevel::INFO) ? std::cout : std::cerr;

    os << "[" << lvl_str(lvl) << "] "
       << "pid=" << getpid() << " "
       << who << ": " << msg
       << std::endl;
}
