#include <cstdint>
#include <memory>
#include <string>
#include <SimuTrace.h>
#include "traceclient.h"
#include "error.h"

using namespace SimuTrace;
namespace traceclient {

SessionId init_session(std::string storage_name, bool create) {
    SessionId session = StSessionCreate("local:/tmp/.simutrace");

    if (session == INVALID_SESSION_ID) {
        throw std::runtime_error("Can't connect to simutrace server!");
    }

    if (create) {
        if (!StSessionCreateStore(session, ("simtrace:" + storage_name).c_str(),
                                  true)) {
            throw SimuTraceException();
        }
    } else {
        if (!StSessionOpenStore(session,
                                ("simtrace:" + storage_name).c_str())) {
            throw SimuTraceException();
        }
    }
    return session;
}

StreamHandle create_stream(SessionId session, std::string stream_name) {
    StreamDescriptor desc;
    auto type = StStreamFindMemoryType(As64Bit, MatWrite, AtVirtual, true);

    if (!StMakeStreamDescriptorFromType(stream_name.c_str(), type, &desc)) {
        throw SimuTraceException();
    }

    auto stream = StStreamRegister(session, &desc);

    auto handle = StStreamAppend(session, stream, nullptr);
    return handle;
}

StreamHandle create_instruction_stream(SessionId session) {
    StreamDescriptor desc;
    if (!StMakeStreamDescriptor("InstructionStream", sizeof(instruction_entry),
                                StreamTypeFlags::StfNone, &desc)) {
        throw SimuTraceException();
    }

    auto stream = StStreamRegister(session, &desc);
    return StStreamAppend(session, stream, nullptr);
}

StreamHandle read_stream(SessionId session, std::string stream_name) {
    StreamId ids[100];
    int count = StStreamEnumerate(session, sizeof(ids), ids);

    for (int i = 0; i < count; i++) {
        StreamQueryInformation info;
        StStreamQuery(session, ids[i], &info);
        printf("%d %s\n", i, info.descriptor.name);

        if (stream_name == info.descriptor.name) {
            return StStreamOpen(session, ids[i], QueryIndexType::QIndex, 0,
                                StreamAccessFlags::SafSequentialScan, nullptr);
        }
    }
    throw std::runtime_error("Could not find stream!");
}
}
