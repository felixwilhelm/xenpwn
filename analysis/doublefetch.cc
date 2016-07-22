/* Opens a simutrace store containing memory traces and searches for potential
 * double fetch vulnerabilities.
 */

#include <map>
#include "traceclient.h"
#include "disasm.h"
#include <SimuTrace.h>
#include <capstone/capstone.h>

std::map<uint64_t, cs_insn*> get_instruction_map(SimuTrace::SessionId session,
                                                 csh cs);

std::pair<uint32_t, std::string> get_module(SimuTrace::SessionId session,
                                            addr_t rip);

std::map<uint64_t, uint32_t> get_cr3_map(SimuTrace::SessionId session);

uint64_t count;

std::map<addr_t, std::set<addr_t>> known;
std::set<std::set<addr_t>> known_sets;
SimuTrace::SessionId session;
csh cs;

void log_double_access(uint64_t addr, std::set<uint64_t>& rips,
                       std::map<uint64_t, cs_insn*>& map,
                       std::map<uint64_t, uint32_t>& cr3_map,
                       SimuTrace::SessionId session) {
    if (known_sets.count(rips) != 0) {
        return;
    }
    known_sets.insert(rips);

    printf("- Double Access for %lx:\n", addr);

    count++;
    for (auto r : rips) {
        auto ins = map[r];

        auto m = get_module(session, ins->address);

        printf("%lx %x (%s + %x): %s %s\n", ins->address, cr3_map[r],
               m.second.c_str(), m.first, ins->mnemonic, ins->op_str);
    }
    printf("-\n");
}

void analyse_stream(SimuTrace::StreamHandle handle) {
    std::map<uint64_t, cs_insn*> instr_map = get_instruction_map(session, cs);
    std::map<uint64_t, uint32_t> cr3_map = get_cr3_map(session);

    std::map<uint64_t, std::set<uint64_t>> access_map;

    auto func = [&cr3_map, &access_map, &instr_map](void* entry) -> void {
        auto e = reinterpret_cast<traceclient::trace_entry*>(entry);

        if (e->address == 0) {
            for (auto v : access_map) {
                if (v.second.size() > 1) {
                    log_double_access(v.first, v.second, instr_map, cr3_map,
                                      session);
                }
            }

            access_map.clear();
            return;
        }

        int size=8;
        if (!e->metadata.fullSize) {
            size = e->data.size / 8;
        }

        // Write
        if (e->metadata.tag) {

            /*
            for (int i=0; i<size; i++)
            {
                access_map[e->address].clear();
            }
            */
                return;
        }
        
        size = 1;
        for (int i=0; i<size; i++)
        {
            access_map[e->address + i].insert(e->ip);
        }

    };

    traceclient::iter_entry(handle, func);

    for (auto v : access_map) {
        if (v.second.size() > 1) {
            log_double_access(v.first, v.second, instr_map, cr3_map, session);
        }
    }
    traceclient::close_stream(handle);
}

int main(int argc, char** argv) {
    cs = disasm::initialize();
    session = traceclient::init_session("trace.sim", false);

    if (argc > 1) {
        auto stream_name = std::string("process ") + argv[1];

        auto handle = traceclient::read_stream(session, stream_name);
        analyse_stream(handle);
    } else {
        auto func =
            [](SimuTrace::StreamHandle h) -> void { analyse_stream(h); };
        traceclient::iter_stream(session, func);
    }

    printf("Total %ld\n", count);
    traceclient::close_session(session);
    return 0;
}

std::map<uint64_t, cs_insn*> get_instruction_map(SimuTrace::SessionId session,
                                                 csh cs) {
    std::map<uint64_t, cs_insn*> result;

    auto handle = traceclient::read_stream(session, "InstructionStream");

    auto func = [cs, &result](void* entry) -> void {
        auto e = reinterpret_cast<traceclient::instruction_entry*>(entry);
        uint64_t rip = e->rip;
        try {
            auto instr = disasm::disassemble(cs, e->bytes, rip);
            result[rip] = instr;
        } catch (CapstoneException e) {
            printf("Can't disassemble %lx\n", rip);
        }
    };

    traceclient::iter_entry(handle, func);
    traceclient::close_stream(handle);
    return result;
}

std::map<uint64_t, uint32_t> get_cr3_map(SimuTrace::SessionId session) {
    std::map<uint64_t, uint32_t> result;

    auto handle = traceclient::read_stream(session, "InstructionStream");

    auto func = [&result](void* entry) -> void {
        auto e = reinterpret_cast<traceclient::instruction_entry*>(entry);
        uint64_t rip = e->rip;
        result[rip] = e->cr3;
    };

    traceclient::iter_entry(handle, func);
    traceclient::close_stream(handle);
    return result;
}

std::pair<uint32_t, std::string> get_module(SimuTrace::SessionId session,
                                            addr_t rip) {
    auto handle = traceclient::read_stream(session, "InstructionStream");

    auto func = [rip](void* entry) -> bool {
        return rip ==
               reinterpret_cast<traceclient::instruction_entry*>(entry)->rip;
    };

    void* tmp = traceclient::find_entry(handle, func);
    auto entry = reinterpret_cast<traceclient::instruction_entry*>(tmp);
    return std::make_pair(entry->offset, std::string(entry->module));
}
