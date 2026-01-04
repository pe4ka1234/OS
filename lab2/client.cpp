#include "log.h"
#include <iostream>

int main() {
    log_msg(LogLevel::INFO, "client", "Вариант 8 — родственная конфигурация: клиенты создаются через fork из host_*.");
    std::cout << "Run host_* executable (e.g., ./host_pipe) to start the lab.\n";
    return 0;
}
