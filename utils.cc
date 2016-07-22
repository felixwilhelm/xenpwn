#include "spdlog/spdlog.h"
#include "libvmi/libvmi.h"
#include "state.h"
#include <signal.h>

#include "utils.h"

namespace utils {
void set_loglevel(int debug) {
    auto level = spdlog::level::warn;
    switch (debug) {
        case 0:
            level = spdlog::level::warn;
            break;
        case 1:
            level = spdlog::level::notice;
            break;
        case 2:
            level = spdlog::level::info;
            break;
        case 3:
            level = spdlog::level::debug;
            break;
        case 4:
            level = spdlog::level::trace;
            break;
    }
    spdlog::set_level(level);
}

std::shared_ptr<spdlog::logger> get_logger(int debug_level,
                                           std::string logfile) {
    set_loglevel(debug_level);
    auto log = (logfile == "") ? spdlog::stdout_logger_st("console")
                               : spdlog::rotating_logger_st(
                                     "log", logfile, 1024 * 1024 * 1024, 100);
    return log;
}

void register_signal_handler(void (*handler)(int)) {
    struct sigaction act;

    act.sa_handler = handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);
}
}
