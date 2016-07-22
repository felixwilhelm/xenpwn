#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <spdlog/spdlog.h>
#include <SimuTrace.h>
#include <memory>

#include "events.h"
#include "traceclient.h"
#include "vmi_helper.h"
#include "state.h"
#include "disasm.h"
#include "modules.h"

State* state = nullptr;

State::State(std::string vmid, std::shared_ptr<spdlog::logger> logger,
             bool partial)
    : logger(logger) {
    uint32_t flags = VMI_XEN | VMI_INIT_EVENTS;
    if (partial) {
        flags |= VMI_INIT_PARTIAL;
    } else {
        flags |= VMI_INIT_COMPLETE;
    }

    if (vmi_init(&vmi, flags, vmid.c_str()) == VMI_FAILURE) {
        logger->error("Failed to init LibVMI library. Aborting!");
        logger->error(
            "You probably used an invalid VM identifier or do not have "
            "sufficient privileges.");
        if (vmi != NULL) {
            vmi_destroy(vmi);
        }
        throw std::runtime_error("Could not initialize libVMI");
    } else {
        logger->info("LibVMI init succeeded!");
    }

    if (vmi_get_ostype(vmi) == VMI_OS_WINDOWS) {
        _modules = modules::get_modules(vmi);

        for (auto m : _modules) {
            printf("%lx %s\n", m.first, m.second.c_str());
        }
    }

    cs_handle = disasm::initialize();
    trace_session = traceclient::init_session("trace.sim", true);
    instruction_stream = traceclient::create_instruction_stream(trace_session);
}

State::~State() {
    logger->info("Cleaning Up!");

    vmi_destroy(vmi);
    traceclient::close_stream(instruction_stream);
    traceclient::close_session(trace_session);
}

void State::disable_tracing_events() {}

cs_insn* disassemble_vm(State* state, addr_t address, addr_t cr3) {
    csh handle = state->cs_handle;
    uint8_t data[15];

    if (vmi::read_bytes(state->vmi, cr3, address, data, 15) != 15) {
        state->logger->error("Can't read 15 instruction bytes from {:#x}",
                             address);
    }

    // Save newly encountered instruction in Simutrace Stream
    auto entry = traceclient::next_instr_entry(state->instruction_stream);

    auto m = modules::find_module(address, state->get_module_list());

    entry->rip = address;
    entry->offset = m.first;
    int length = m.second.length() > 49 ? 49 : m.second.length();
    strncpy(entry->module, m.second.c_str(), length);
    entry->module[49] = 0;
    memcpy(entry->bytes, data, sizeof(entry->bytes));
    entry->cr3 = cr3;
    traceclient::submit(state->instruction_stream);

    return disasm::disassemble(handle, data, address);
}

/* Get disassmbled instruction at virtual kernel address addr.
 * TODO: Support different contexts*/
cs_insn* State::get_instruction(addr_t addr, addr_t cr3) {
    auto ins = instruction_map.find(addr);
    if (ins == end(instruction_map)) {
        auto new_instruction = disassemble_vm(this, addr, cr3);
        instruction_map[addr] = new_instruction;

        state->logger->info("Encountered new instruction: {:#x} {} {}", addr,
                            new_instruction->mnemonic, new_instruction->op_str);
        return new_instruction;
    }
    return ins->second;
}
