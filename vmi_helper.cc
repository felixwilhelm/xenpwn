#include <libvmi/libvmi.h>
#include <string>
#include <stdlib.h>
#include "vmi_helper.h"
#include "error.h"

namespace vmi {
// Copied from libvmi dump-memory
size_t dump_memory(vmi_instance_t vmi, std::string filename) {
    FILE *f = NULL;
    f = fopen(filename.c_str(), "w");
    if (f == NULL) {
        return 0;
    }

    auto size = vmi_get_memsize(vmi);
    addr_t address = 0;
    const int page_size = 1 << 12;

    uint8_t page[page_size];
    uint8_t zeros[page_size];
    memset(zeros, 0, page_size);

    while (address < size) {
        if (vmi_read_pa(vmi, address, page, page_size) == page_size) {
            fwrite(page, 1, page_size, f);
        } else {
            fwrite(zeros, 1, page_size, f);
        }
        address += page_size;
    }
    fclose(f);
    return size;
}

uint16_t read_word(vmi_instance_t vmi, addr_t dtb, addr_t va) {
    auto phys_address = vmi_pagetable_lookup(vmi, dtb, va);
    uint16_t value;

    if (vmi_read_16_pa(vmi, phys_address, &value) != VMI_SUCCESS) {
        std::string w = "Read from physical address" +
                        std::to_string(phys_address) + "failed";
        throw VMIException(w);
    }
    return value;
}

uint32_t read_dword(vmi_instance_t vmi, addr_t dtb, addr_t va) {
    auto phys_address = vmi_pagetable_lookup(vmi, dtb, va);
    uint32_t value;

    if (vmi_read_32_pa(vmi, phys_address, &value) != VMI_SUCCESS) {
        std::string w = "Read from physical address" +
                        std::to_string(phys_address) + "failed";
        throw VMIException(w);
    }
    return value;
}

addr_t read_ptr(vmi_instance_t vmi, addr_t dtb, addr_t va) {
    auto phys_address = vmi_pagetable_lookup(vmi, dtb, va);
    addr_t value;

    if (vmi_read_64_pa(vmi, phys_address, &value) != VMI_SUCCESS) {
        std::string w = "Read from physical address" +
                        std::to_string(phys_address) + "failed";
        throw VMIException(w);
    }
    return value;
}

uint8_t read_bytes(vmi_instance_t vmi, addr_t dtb, addr_t va, uint8_t *dataptr,
                   uint8_t size) {
    auto phys_address = vmi_pagetable_lookup(vmi, dtb, va);
    return vmi_read_pa(vmi, phys_address, dataptr, size);
}
}
