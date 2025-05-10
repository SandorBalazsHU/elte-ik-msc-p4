#include "headers.p4"
#include "actions.p4"

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta) {

    table tcp_table {
        key = {
            hdr.tcp.flags : exact;
        }
        actions = {
            send_synack;
            send_dummy_response;
            nop;
        }
        size = 16;
        default_action = nop();
    }

    apply {
        if (hdr.tcp.isValid() && hdr.ipv4.isValid()) {
            tcp_table.apply();
        }
    }
}
