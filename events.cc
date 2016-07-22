#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <memory>
#include "state.h"
#include "events.h"
#include "error.h"

typedef vmi_event_t *event_ptr;

event_ptr new_memevent(State *s, addr_t paddr,
                       vmi_memevent_granularity_t granularity,
                       vmi_mem_access_t access, event_callback_t callback,
                       bool _register) {
    auto event = new vmi_event_t();
    event->type = VMI_EVENT_MEMORY;
    event->mem_event.physical_address = paddr;
    event->mem_event.npages = 1;
    event->mem_event.granularity = granularity;
    event->mem_event.in_access = access;
    event->callback = callback;

    s->logger->debug("Registering mem event for address: {}", paddr);

    if (_register) {
        if (vmi_register_event(s->vmi, event) != VMI_SUCCESS) {
            s->logger->debug("Could not register mem event for address: {}",
                             paddr);
            throw VMIException("Failed to register memory event!");
        }
    }
    return event;
}

event_ptr new_page_memevent(State *s, addr_t paddr, vmi_mem_access_t access,
                            event_callback_t callback) {
    return new_memevent(s, paddr, VMI_MEMEVENT_PAGE, access, callback, true);
}

event_ptr new_byte_memevent(State *s, addr_t paddr, vmi_mem_access_t access,
                            event_callback_t callback) {
    return new_memevent(s, paddr, VMI_MEMEVENT_BYTE, access, callback, true);
}

event_ptr new_regevent(State *s, registers_t reg, event_callback_t callback,
                       bool _register) {
    auto event = new vmi_event_t();
    event->type = VMI_EVENT_REGISTER;
    event->reg_event.reg = reg;
    event->reg_event.in_access = VMI_REGACCESS_W;
    event->callback = callback;

    s->logger->debug("Registering reg write event for register: {}", reg);

    if (_register) {
        if (vmi_register_event(s->vmi, event) != VMI_SUCCESS) {
            s->logger->error(
                "Could not register reg write event for register: {}", reg);
            throw VMIException("Failed to register memory event!");
        }
    }

    return event;
}
