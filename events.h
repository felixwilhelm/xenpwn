/* events.h - defines several helper functions that can be used to create and
 * register libvmi/xen memory and register write events.
 */

#pragma once
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <memory>
#include "state.h"

/* typedef for easier handling of vmi_event_t structures. */
typedef vmi_event_t *event_ptr;

/* All of the following function can throw an exception if registering fails.
 * */

/* Creates a new memory event and automatically registers it if the last
 * parameter is true */
event_ptr new_memevent(State *s, addr_t paddr,
                       vmi_memevent_granularity_t granularity,
                       vmi_mem_access_t access, event_callback_t callback,
                       bool _register = true);

/* Creates a new memory event with page granularity and automatically registers
 * it*/
event_ptr new_page_memevent(State *s, addr_t paddr, vmi_mem_access_t access,
                            event_callback_t callback);

/* Creates a new memory event with byte granularity and automatically registers
 * it*/
event_ptr new_byte_memevent(State *s, addr_t paddr, vmi_mem_access_t access,
                            event_callback_t callback);

/* Creates a new register write event and registers it if the last parameter is
 * true */
event_ptr new_regevent(State *s, registers_t reg, event_callback_t callback,
                       bool _register = true);
