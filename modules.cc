#include <vector>
#include <string>
#include <algorithm>
#include <libvmi/libvmi.h>
#include "modules.h"

namespace modules {

module_list get_modules(vmi_instance_t vmi) {
    module_list result;
    // Copied after libvmi example module-list
    addr_t next_module;
    addr_t list_head;

    vmi_read_addr_ksym(vmi, (char *)"PsLoadedModuleList", &next_module);

    list_head = next_module;

    while (true) {
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, 0, &tmp_next);

        if (list_head == tmp_next) {
            break;
        }

        unicode_string_t *us = NULL;
        unicode_string_t out;

        uint64_t base;
        vmi_read_addr_va(vmi, next_module + 0x30, 0, &base);

        us = vmi_read_unicode_str_va(vmi, next_module + 0x58, 0);

        if (us && vmi_convert_str_encoding(us, &out, "UTF-8") == VMI_SUCCESS) {
            std::string s = reinterpret_cast<char *>(out.contents);
            result.push_back(std::make_pair(base, s));
            free(out.contents);
        }
        if (us) {
            vmi_free_unicode_str(us);
        }

        next_module = tmp_next;
    }

    sort(result.begin(), result.end(),
         [](const list_entry &a, const list_entry &b) -> bool {
             return a.first < b.first;

         });
    return result;
}

std::pair<uint32_t, std::string> find_module(uint64_t address,
                                             module_list &modules) {
    list_entry *e = nullptr;
    for (auto &p : modules) {
        if (address < p.first) {
            break;
        }
        e = &p;
    }

    if (e == nullptr) {
        return std::make_pair(0, "INVALID");
    }

    return std::make_pair(e->first - address, e->second);
}
}
