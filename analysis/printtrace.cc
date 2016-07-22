#include "traceclient.h"
#include <SimuTrace.h>
#include <map>
#include <vector>
#include <algorithm>


std::map<long,long> count_map;

long c_total=0;
long c_unprivileged = 0;
long c_read = 0;
long c_write = 0;
long c_size[4] {0,0,0,0};

int main(int argc, char** argv) {
    if (argc < 2) {
        return 0;
    }

    auto stream_name = std::string("process ") + argv[1];

    printf("%s\n", stream_name.c_str());
    auto session = traceclient::init_session("trace.sim", false);
    auto handle = traceclient::read_stream(session, stream_name);

    auto print_entry = [](void* entry) -> void {
        c_total+=1;
        auto e = reinterpret_cast<traceclient::trace_entry*>(entry);
        char w = (e->metadata.tag) ? 'w' : 'r';
        printf("rip %lx, address %lx %c\n", e->ip, e->address, w);
        count_map[e->ip]++;

        if (e->ip == 0x00) {
            c_unprivileged +=1;
        } else {
            if (e->metadata.tag) {c_write++;}
            else {c_read++;}

            if (e->metadata.fullSize) {c_size[3]++;}
            else {
                switch (e->data.size) {
                    case 32:
                        c_size[2]++;
                        break;
                    case 16:
                        c_size[1]++;
                        break;
                    case 8:
                        c_size[0]++;
                        break;
                    }
                }
                
            }

    };

    traceclient::iter_entry(handle, print_entry);

    traceclient::close_stream(handle);
    traceclient::close_session(session);

    std::vector<std::pair<long, long>> top_four(4);
    std::partial_sort_copy(count_map.begin(),
                           count_map.end(),
                           top_four.begin(),
                           top_four.end(),
                           [](std::pair<long, long> const& l,
                              std::pair<long, long> const& r)
                           {
                               return l.second > r.second;
                           });
    for (auto p : top_four)
    {
        printf("rip: %lx - %lu\n", p.first,p.second);

    }

    printf("total: %lu , read: %lu, write: %lu\n", c_total, c_read, c_write);
    printf("8: %lu , 16: %lu, 32: %lu 64: %lu\n", c_size[0], c_size[1], c_size[2], c_size[3]);
    return 0;
}
