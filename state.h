#pragma once

#include <memory>
#include <set>
#include <map>
#include <vector>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <spdlog/spdlog.h>
#include <SimuTrace.h>
#include <capstone/capstone.h>

#include "traceclient.h"
#include "modules.h"

typedef vmi_event_t* event_ptr;

class Process;

/* The almighty State class.
 * Due to our current use of libvmi, the event handler functions can't
 * get passed any additional arguments. Therefore we need a global
 * state object holding all relevant information.
 * An advantage of this approach is that State is responsible for the handling
 * of all simutrace and libvmi ressources. As long as the State destructor
 * executes, we should never be in a
 * situation where a zombie event hangs our VM.
 */
class State {
   private:
    // Map from instruction pointer to disassembled capstone instruction.
    // Used to minimize diassembler invocations for often triggered instruction
    // pointers. Because addr_t is global (context independent) this only works
    // for kernel instructions.
    // TODO: Improve this for hypervisor usage.
    std::map<addr_t, cs_insn*> instruction_map;

    // Are we currently tracing memory accesses
    bool tracing = false;

    // List of loaded kernel modules and their base addresses
    // Used to add module information to the instruction trace
    modules::module_list _modules;

   public:
    bool interrupted = 0;

    // Number of triggered trace events. Used as counter for simutrace stream
    unsigned long long count = 0;

    // Session identifier to talk to the simutrace session. Only one session is
    // open at the same time.
    // But we might have multiple stream descriptors for each
    // traced process, these are stored directly in the process class.
    SimuTrace::SessionId trace_session;

    // Simutrace stream to store all encountered instructions.
    SimuTrace::StreamHandle instruction_stream;

    // Main libvmi handle used for all VM introspection functions.
    vmi_instance_t vmi;

    // Capstone handle used for disassembly functions.
    csh cs_handle;

    // SPDLOG logger object used for all output/error reporting
    std::shared_ptr<spdlog::logger> logger;

    /* Constructs a State object. Arguments are the VM identifier of the target
     * Xen VM,
     * an spdlog::logger object used for diagnostics output and the pid of the
     * process that should be traced.
     * -1 equals all processes. This constructor might throw a runtime_exception
     * if initialization of the libvmi library fails. */
    State(std::string vmid, std::shared_ptr<spdlog::logger> logger,
          bool partial = false);

    /* Destructor of State object. Clears all vmi events to ensure further
     * execution of VM. Closes simutrace session */
    ~State();

    /* Disable all tracing events. Called when execution is in user space
     * or in wrong context*/
    void disable_tracing_events();

    cs_insn* get_instruction(addr_t addr, addr_t cr3);

    modules::module_list& get_module_list() { return _modules; }
};

extern State* state;
;
