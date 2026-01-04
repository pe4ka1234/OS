#include "common.h"
#include "pidfile.h"
#include "config.h"
#include "fs_utils.h"
#include "daemon_app.h"
#include "daemonize.h"

static void ensure_singleton_with_pidfile() {
    auto existing = read_pidfile(PIDFILE_PATH);
    if (existing && *existing > 0) {
        pid_t pid = *existing;
        std::string proc_dir = std::string("/proc") + "/" + std::to_string(pid);
        if (!fs::exists(proc_dir)) {
            syslog(LOG_WARNING, "stale pidfile found for pid=%d; overwriting", (int)pid);
            return;
        }
        syslog(LOG_ERR, "already running with pid=%d (pidfile %s)", (int)pid, PIDFILE_PATH);
        std::exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    fs::path conf_path = DEFAULT_CONF_NAME;
    if (argc >= 2) {
        conf_path = argv[1];
    }

    daemonize();

    openlog("lab1d", LOG_PID | LOG_CONS, LOG_DAEMON);

    ensure_singleton_with_pidfile();

    pid_t self = getpid();
    if (!write_pidfile(PIDFILE_PATH, self)) {
        syslog(LOG_ERR, "cannot write pidfile: %s", PIDFILE_PATH);
    }

    std::signal(SIGHUP,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    DaemonApp::instance().set_initial_config_path(conf_path);

    syslog(LOG_INFO, "daemon started (pid=%d), config='%s'", (int)self, conf_path.c_str());
    DaemonApp::instance().run();

    syslog(LOG_INFO, "daemon stopped");
    closelog();

    return 0;
}