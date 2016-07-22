#include <iostream>
#include <set>
#include "spdlog/spdlog.h"
#include "cmdline/cmdline.h"
#include "utils.h"
#include "error.h"
#include "state.h"
#include "events.h"
#include "vmi_helper.h"

void main_loop(std::string log, int debug, std::string vmid);

std::vector<std::pair<addr_t, uint16_t>> get_domains(State* s);
std::vector<addr_t> get_granttable_frames(State* s, addr_t domain_ptr);

std::unordered_map<addr_t, event_ptr> grant_events;
event_ptr reparse_event;

addr_t target_domain;

SimuTrace::StreamHandle stream;

int main(int argc, char** argv) {
    cmdline::parser parser;

    parser.add<int>("debug", 'd', "debug level (0-5)", false, 2,
                    cmdline::range(0, 5));
    parser.add<std::string>("log", 'l', "log file (default stdout)", false, "");
    parser.add("help", 'h', "print this message");
    parser.footer("VMID");

    bool ok = parser.parse(argc, argv);

    if (!ok || parser.exist("help") || parser.rest().size() != 1) {
        std::cerr << parser.usage();
        std::cerr << "Examples:\n./xentrace -d 4 -l /tmp/memtrace.log "
                     "hvm_xen\n";
        std::cerr << "./memtrace hvm_xen\n";
        return -1;
    }

    std::cout
        << "                           _                     \n"
           "  _ __ ___   ___ _ __ ___ | |_ _ __ __ _  ___ ___\n"
           " | '_ ` _ \\ / _ \\ '_ ` _ \\| __| '__/ _` |/ __/ _ \\\n"
           " | | | | | |  __/ | | | | | |_| | | (_| | (_|  __/\n"
           " |_| |_| |_|\\___|_| |_| |_|\\__|_|  \\__,_|\\___\\___|\n\n\n";
    std::cout << "XEN Edition\n";

    main_loop(parser.get<std::string>("log"), parser.get<int>("debug"),
              parser.rest()[0]);

    // main_loop should not return;

    return 1;
}

void close_handler(int) { state->interrupted = true; }

uint16_t get_domid() {
    reg_t rsp, cr3;
    vmi_get_vcpureg(state->vmi, &rsp, SYSENTER_ESP, 0);
    vmi_get_vcpureg(state->vmi, &cr3, CR3, 0);

    const int stack_size = 4096 << 3;

    addr_t current = (rsp & (~(stack_size - 1))) + stack_size - 232 + 208;
    addr_t vcpu = vmi::read_ptr(state->vmi, cr3, current);
    addr_t domain = vmi::read_ptr(state->vmi, cr3, vcpu + 16);

    return vmi::read_word(state->vmi, cr3, domain);
}

void xen_trace_event(vmi_instance_t vmi, event_ptr event);

void reparse_grant_table(vmi_instance_t vmi, event_ptr event) {
    vmi_clear_event(vmi, event);
    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    state->logger->debug("Grant Table Change!");

    auto old_grant_events = grant_events;
    auto frames = get_granttable_frames(state, target_domain);

    std::unordered_map<addr_t, event_ptr> new_events;

    // Add newly added frames.
    for (auto f : frames) {
        if (old_grant_events.count(f) > 0) {
            new_events[f] = old_grant_events[f];
        } else {
            try {
                auto ev = new_page_memevent(state, f, VMI_MEMACCESS_RWX,
                                            xen_trace_event);
                new_events[f] = ev;
                state->logger->debug("Registered page event {:x}", f);

            } catch (const VMIException& e) {
                state->logger->error("Can't register page event {:x}", f);
            }
        }
    }

    // Remove old frames.
    for (auto p : old_grant_events) {
        if (std::find(frames.begin(), frames.end(), p.first) == frames.end()) {
            vmi_clear_event(state->vmi, p.second);
        }
    }

    grant_events = new_events;
}

void xen_trace_event(vmi_instance_t vmi, event_ptr event) {
    reg_t rip, cr3;
    vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

    uint16_t domid = get_domid();
    if (domid != 0 && !(rip > 0xffff82d080000000 && rip < 0xffff82d0bfffffff)) {
        vmi_clear_event(vmi, event);
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

        auto entry = traceclient::next_entry(stream);

        entry->ip = 0;
        entry->address = 0;
        entry->metadata.cycleCount = state->count++;
        entry->metadata.fullSize = 1;
        entry->data.data64 = 0;

        traceclient::submit(stream);
        return;
    }

    cs_insn* instruction;
    try {
        instruction = state->get_instruction(rip, cr3);
    } catch (CapstoneException e) {
        // Disassembling of the executed instruction failed.
        // We don't have much choice other than returning.
        // TODO: Log and investigate!
        vmi_clear_event(vmi, event);
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return;
    }

    // The size of the memory access
    int size;
    if (instruction->detail == nullptr) {
        size = 4;
        state->logger->error("Missing instruction details!");
    } else {
        size = instruction->detail->x86.operands[0].size;
    }

    auto entry = traceclient::next_entry(stream);

    entry->ip = rip;
    entry->address = event->mem_event.gla;
    entry->metadata.cycleCount = state->count++;
    if (size == 8) {
        entry->metadata.fullSize = 1;
        entry->data.data64 = 0;
    } else if (size == 4) {
        entry->data.size = 4 * 8;
        entry->data.data32 = 0;
    } else if (size == 2) {
        entry->data.size = 2 * 8;
        entry->data.data16 = 0;
    } else if (size == 1) {
        entry->data.size = 8;
        entry->data.data8 = 0;
    } else {
        state->logger->error(
            "Invalid address_size {} in disassembled instruction!", size);
    }

    entry->metadata.tag =
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 1 : 0;

    traceclient::submit(stream);

    vmi_clear_event(vmi, event);
    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
}

void main_loop(std::string logfile, int debug, std::string vmid) {
    /* Set loglevel to the command line argument. If no logfile was
     * specified we
     * log to STDOUT, otherwise use a rotating_log_file*/
    utils::set_loglevel(debug);
    auto log = utils::get_logger(debug, logfile);

    log->debug("Registering signal handler..");

    /* Make sure signals are catched and handled safely. If we do not
     * deregister our vmi events correctly, the virtual machine would hang
     * completely when our program quits.
     */
    utils::register_signal_handler(close_handler);

    log->debug("Initializing libVMI");

    State s(vmid, log, true);
    state = &s;

    auto domains = get_domains(state);
    if (domains.size() == 1) {
        log->error("Only one domain running in this Xen target!");
        state->interrupted = true;
        traceclient::close_stream(stream);
        return;
    }
    target_domain = domains.back().first;

    // Reparse the grant tables after every do_grant_op hypercall

    // Address of ret instruction inside do_grant_table_op;
    long do_grant_table_op = 0xffff82d08010f4f8;
    // 0xffff82d08010f487;

    reg_t cr3;
    vmi_get_vcpureg(state->vmi, &cr3, CR3, 0);

    auto p_grant = vmi_pagetable_lookup(state->vmi, cr3, do_grant_table_op);
    reparse_event =
        new_byte_memevent(state, p_grant, VMI_MEMACCESS_X, reparse_grant_table);

    stream = traceclient::create_stream(state->trace_session, "process 0");

    auto frames = get_granttable_frames(state, target_domain);

    for (auto f : frames) {
        try {
            auto ev =
                new_page_memevent(state, f, VMI_MEMACCESS_RWX, xen_trace_event);
            grant_events[f] = ev;
            state->logger->debug("Registered page event {:x}", f);

        } catch (const VMIException& e) {
            state->logger->debug("Can't register page event {}", f);
        }
    }

    // Wait for events.
    status_t status = VMI_SUCCESS;
    while (!state->interrupted) {
        log->debug("Waiting for events...");
        status = vmi_events_listen(state->vmi, 500);
        if (status != VMI_SUCCESS) {
            log->error("Error waiting for events! Quitting...");
            state->interrupted = true;
        }
    }

    log->info("Leaving main_loop");
    vmi_clear_event(state->vmi, reparse_event);
    for (auto e : grant_events) {
        vmi_clear_event(state->vmi, e.second);
    }
    traceclient::close_stream(stream);
}

std::vector<std::pair<addr_t, uint16_t>> get_domains(State* s) {
    std::vector<std::pair<addr_t, uint16_t>> domains;

    addr_t domain_list = 0xffff82d0802ce100;  // Xen 4.5  Ubuntu
    // 0xffff82d0802d6198; // SLES XEN
    reg_t cr3;
    vmi_get_vcpureg(s->vmi, &cr3, CR3, 0);
    addr_t dom_ptr = vmi::read_ptr(s->vmi, cr3, domain_list);

    const int offset_next = 104;

    while (dom_ptr != 0) {
        uint16_t domid = vmi::read_word(s->vmi, cr3, dom_ptr);
        state->logger->info("Domain found: {:x} {}", dom_ptr, domid);
        domains.push_back(std::make_pair(dom_ptr, domid));
        dom_ptr = vmi::read_ptr(s->vmi, cr3, dom_ptr + offset_next);
    }
    return domains;
}
struct active_grant_entry {
    uint32_t pin;   /* Reference count information.             */
    uint16_t domid; /* Domain being granted access.             */
    struct domain* trans_domain;
    uint32_t trans_gref;
    unsigned long frame;      /* Frame being granted.                     */
    unsigned long gfn;        /* Guest's idea of the frame being granted. */
    unsigned is_sub_page : 1; /* True if this is a sub-page grant. */
    unsigned start : 15;      /* For sub-page grants, the start offset
                                 in the page.                           */
    unsigned length : 16;     /* For sub-page grants, the length of the
                                 grant.                                */
};

addr_t get_entry_addr(State* s, addr_t cr3, addr_t active_table, int offset) {
    auto active = active_table;
    const int per_page = 4096 / sizeof(active_grant_entry);

    auto column_addr = active + (offset / per_page) * 8;
    auto column = vmi::read_ptr(s->vmi, cr3, column_addr);

    return column + ((offset % per_page) * sizeof(active_grant_entry));
}

std::vector<addr_t> get_granttable_frames(State* s, addr_t domain_ptr) {
    std::vector<addr_t> frames;

    const int grant_table_offset = 200;
    reg_t cr3;
    vmi_get_vcpureg(state->vmi, &cr3, CR3, 0);
    auto grant_table =
        vmi::read_ptr(s->vmi, cr3, domain_ptr + grant_table_offset);

    auto nr_grant_frames = vmi::read_dword(s->vmi, cr3, grant_table);
    auto active_grant_ptr = vmi::read_ptr(s->vmi, cr3, grant_table + 32);
    auto version = vmi::read_dword(s->vmi, cr3, grant_table + 60);

    auto grant_entries = (nr_grant_frames << 12) / 16;

    if (version == 1) {
        grant_entries *= 2;
    }

    state->logger->debug("Number of Grant Entries: {:d} {:x} {}", grant_entries,
                         active_grant_ptr, version);

    for (uint i = 0; i < grant_entries; i++) {
        addr_t active_grant = get_entry_addr(s, cr3, active_grant_ptr, i);
        auto frame = vmi::read_ptr(s->vmi, cr3, active_grant + 24);
        auto pin = vmi::read_dword(s->vmi, cr3, active_grant);
        if (!pin) {
            continue;
        }

        if (frame != 0) {
            frames.push_back(frame * 4096);
        }
    }

    return frames;
}
