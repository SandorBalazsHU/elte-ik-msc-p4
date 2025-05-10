#include <core.p4>
#include "headers.p4"
#include "parser.p4"
#include "control.p4"

control MyVerifyChecksum(...) { apply { } }
control MyComputeChecksum(...) { apply { } }
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
