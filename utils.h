#pragma once
#include "spdlog/spdlog.h"
#include "libvmi/libvmi.h"
#include "state.h"
#include <signal.h>

namespace utils {
/* Helper function to translate the debug value supplied via command line
 * into a loglevel as defined by our logging library. The supplied value is
 * used as global setting for spdlog. */
void set_loglevel(int debug);

// Get a logger object for use by the state class
std::shared_ptr<spdlog::logger> get_logger(int debug_level,
                                           std::string logfile);

// Register a handler that catch all signals and set the state->interrupt flag
// to true
// This is needed so all libvmi events are deregistered correctly.
void register_signal_handler(void (*handler)(int));
}
