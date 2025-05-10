#include <core.p4>
#include <v1model.p4>

// Ethernet header
header ethernet_t {
    mac_addr dstAddr;
    mac_addr srcAddr;
    bit<16>  etherType;
}

// IPv4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

// TCP header
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// Dummy payload header (16 bytes)
header payload_t {
    bit<8>[16] data;
}

// Header union
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    payload_t  payload;
}

// Metadata (not used here)
struct metadata_t {}

// Parser
parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

// Actions
action send_synack() {
    modify_field(hdr.ethernet.dstAddr, hdr.ethernet.srcAddr);
    modify_field(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);

    modify_field(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr);
    modify_field(hdr.ipv4.srcAddr, 0x0a000002); // 10.0.0.2

    modify_field(hdr.tcp.dstPort, hdr.tcp.srcPort);
    modify_field(hdr.tcp.srcPort, 12345);
    modify_field(hdr.tcp.flags, 0x12); // SYN+ACK

    // payload not added here
}

action send_dummy_response() {
    modify_field(hdr.ethernet.dstAddr, hdr.ethernet.srcAddr);
    modify_field(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);

    modify_field(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr);
    modify_field(hdr.ipv4.srcAddr, 0x0a000002); // 10.0.0.2

    modify_field(hdr.tcp.dstPort, hdr.tcp.srcPort);
    modify_field(hdr.tcp.srcPort, 12345);
    modify_field(hdr.tcp.flags, 0x18); // PSH+ACK

    // Add payload content: "Hi from switch!"
    hdr.payload.setValid();
    hdr.payload.data[0]  = 0x48; // H
    hdr.payload.data[1]  = 0x69; // i
    hdr.payload.data[2]  = 0x20; //  
    hdr.payload.data[3]  = 0x66; // f
    hdr.payload.data[4]  = 0x72; // r
    hdr.payload.data[5]  = 0x6f; // o
    hdr.payload.data[6]  = 0x6d; // m
    hdr.payload.data[7]  = 0x20; //  
    hdr.payload.data[8]  = 0x73; // s
    hdr.payload.data[9]  = 0x77; // w
    hdr.payload.data[10] = 0x69; // i
    hdr.payload.data[11] = 0x74; // t
    hdr.payload.data[12] = 0x63; // c
    hdr.payload.data[13] = 0x68; // h
    hdr.payload.data[14] = 0x21; // !
    hdr.payload.data[15] = 0x00; // null/padding
}

// Table
table tcp_table {
    key = {
        hdr.tcp.flags: exact;
    }
    actions = {
        send_synack;
        send_dummy_response;
        NoAction;
    }
    size = 4;
}

// Ingress
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            tcp_table.apply();
        }
    }
}

// Egress (not used)
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// Deparser
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        if (hdr.payload.isValid()) {
            packet.emit(hdr.payload);
        }
    }
}

// Pipeline
V1Switch(
    MyParser(),
    MyIngress(),
    MyEgress(),
    MyDeparser()
) main;
