#pragma once
#include <vector>
#include <map>
#include <libvmi/libvmi.h>
namespace modules {

typedef std::pair<addr_t, std::string> list_entry;
typedef std::vector<list_entry> module_list;
std::vector<std::pair<addr_t, std::string>> get_modules(vmi_instance_t vmi);

std::pair<uint32_t, std::string> find_module(uint64_t address,
                                             module_list &modules);
}
