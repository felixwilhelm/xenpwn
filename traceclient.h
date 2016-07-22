#pragma once
#include <cstdint>
#include <string>
#include <SimuTrace.h>

namespace traceclient {

typedef SimuTrace::DataWrite64 trace_entry;

typedef struct _instruction {
    uint64_t rip;
    uint8_t bytes[15];
    char module[50];
    uint32_t offset;
    uint32_t cr3;
} instruction_entry;

SimuTrace::SessionId init_session(std::string storage_name, bool create);
SimuTrace::StreamHandle create_stream(SimuTrace::SessionId session,
                                      std::string stream_name);

SimuTrace::StreamHandle create_instruction_stream(SimuTrace::SessionId session);
SimuTrace::StreamHandle read_stream(SimuTrace::SessionId session,
                                    std::string stream_name);

inline trace_entry *next_entry(SimuTrace::StreamHandle &handle) {
    return reinterpret_cast<trace_entry *>(
        SimuTrace::StGetNextEntryFast(&handle));
}

inline instruction_entry *next_instr_entry(SimuTrace::StreamHandle &handle) {
    return reinterpret_cast<instruction_entry *>(
        SimuTrace::StGetNextEntryFast(&handle));
}

inline void submit(SimuTrace::StreamHandle &handle) {
    SimuTrace::StSubmitEntryFast(handle);
}

inline void close_stream(SimuTrace::StreamHandle handle) {
    SimuTrace::StStreamClose(handle);
}

inline void close_session(SimuTrace::SessionId session) {
    SimuTrace::StSessionClose(session);
}

template <typename Lambda>
void iter_entry(SimuTrace::StreamHandle &handle, Lambda &&func) {
    void *entry = SimuTrace::StGetNextEntryFast(&handle);

    while (entry != nullptr) {
        std::forward<Lambda>(func)(entry);
        entry = SimuTrace::StGetNextEntryFast(&handle);
    }
}

template <typename Lambda>
void *find_entry(SimuTrace::StreamHandle &handle, Lambda &&func) {
    void *entry = SimuTrace::StGetNextEntryFast(&handle);

    while (entry != nullptr) {
        if (std::forward<Lambda>(func)(entry)) {
            return entry;
        }
        entry = SimuTrace::StGetNextEntryFast(&handle);
    }
    return nullptr;
}

template <typename Lambda>
void iter_stream(SimuTrace::SessionId session, Lambda &&func) {
    using namespace SimuTrace;
    StreamId ids[1000];
    int count = StStreamEnumerate(session, sizeof(ids), ids);

    for (int i = 0; i < count; i++) {
        StreamQueryInformation info;
        StStreamQuery(session, ids[i], &info);

        if (!strncmp(info.descriptor.name, "process", strlen("process"))) {
            auto handle =
                StStreamOpen(session, ids[i], QueryIndexType::QIndex, 0,
                             StreamAccessFlags::SafSequentialScan, nullptr);
            func(handle);
        }
    }
}
}
