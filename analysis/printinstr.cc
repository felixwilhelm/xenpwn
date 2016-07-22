
#include "traceclient.h"
#include <SimuTrace.h>
#include "disasm.h"
#include <capstone/capstone.h>

int main(int, char**) {
    auto session = traceclient::init_session("trace.sim", false);

    auto handle = traceclient::read_stream(session, "InstructionStream");

    csh cs = disasm::initialize();

    auto print_instr = [cs](void* entry) -> void {
        auto e = reinterpret_cast<traceclient::instruction_entry*>(entry);
        uint64_t rip = e->rip;
        try {
            auto ins = disasm::disassemble(cs, e->bytes, rip);
            printf("%lx %s %s\n", ins->address, ins->mnemonic, ins->op_str);

        } catch (CapstoneException e) {
            printf("Can't disassemble %lx\n", rip);
        }
    };

    traceclient::iter_entry(handle, print_instr);

    traceclient::close_stream(handle);
    traceclient::close_session(session);
    return 0;
}
