// disasm.h is a minimal wrapper around capstone to allow easy
// disassembling of single instructions.
#pragma once
#include <map>
#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include "state.h"
#include "error.h"

namespace disasm {

// Initializes a new capstone handle for x64 with full details
// Throws a CapstoneException on error.
csh initialize() {
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)) {
        throw CapstoneException(handle);
    }
    return handle;
}

// Disassembles a single instructions and returns a pointer to a
// cs_insn * instruction. This needs to be freed manually!
// bytes should always be at least 15 bytes long.
// Throws a CapstoneException if no instruction was returned.
cs_insn* disassemble(csh cs, uint8_t* bytes, addr_t address) {
    cs_insn* ret;
    if (cs_disasm(cs, bytes, 15, address, 1, &ret) == 0) {
        throw CapstoneException(cs);
    }
    return ret;
}
}
