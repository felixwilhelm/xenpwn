#pragma once
#include <libvmi/libvmi.h>
#include <string>
namespace vmi {
size_t dump_memory(vmi_instance_t vmi, std::string filename);

// VMI helper: Read a word from a physical address
uint16_t read_word(vmi_instance_t vmi, addr_t dtb, addr_t va);

// VMI helper: Read a dword from a physical address
uint32_t read_dword(vmi_instance_t vmi, addr_t dtb, addr_t va);

// VMI helper: Read a qword from a physical address
addr_t read_ptr(vmi_instance_t vmi, addr_t dtb, addr_t va);

// VMI helper: Read an arbitrary number of bytes from a physical address
uint8_t read_bytes(vmi_instance_t vmi, addr_t dtb, addr_t va, uint8_t *dataptr,
                   uint8_t size);
}
