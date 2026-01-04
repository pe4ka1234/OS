#pragma once
#include <string>

enum class LogLevel { INFO, WARN, ERROR };

void log_msg(LogLevel lvl, const std::string& who, const std::string& msg);
