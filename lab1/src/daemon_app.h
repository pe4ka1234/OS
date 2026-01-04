#pragma once
#include "common.h"
#include "config.h"
#include "fs_utils.h"

class DaemonApp {
public:
    static DaemonApp& instance() {
        static DaemonApp app;
        return app;
    }

    void set_initial_config_path(fs::path p) {
        std::error_code ec;
        conf_path_ = fs::absolute(p, ec);
        if (ec) conf_path_ = p;
    }

    void run() {
        reload_config();

        while (!g_terminate.load()) {
            if (g_reload.load()) {
                g_reload.store(false);
                reload_config();
            }

            execute_once();

            int sleep_total = g_interval_sec.load();
            for (int i = 0; i < sleep_total && !g_terminate.load() && !g_reload.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

private:
    DaemonApp() = default;

    void reload_config() {
        rules_ = load_config_lines(conf_path_);
    }

    void execute_once() {
        for (const auto& r : rules_) {
            std::uintmax_t sz = dir_size_recursive(r.folder);
            if (sz > r.threshold_bytes) {
                syslog(LOG_INFO,
                       "rule: folder '%s' size=%ju > %ju -> cleaning",
                       r.folder.c_str(),
                       static_cast<uintmax_t>(sz),
                       static_cast<uintmax_t>(r.threshold_bytes));

                remove_contents_of(r.folder);
            } else {
                syslog(LOG_DEBUG,
                       "rule: folder '%s' size=%ju <= %ju -> ok",
                       r.folder.c_str(),
                       static_cast<uintmax_t>(sz),
                       static_cast<uintmax_t>(r.threshold_bytes));
            }
        }
    }

private:
    fs::path conf_path_{DEFAULT_CONF_NAME};
    std::vector<Rule> rules_;
};
