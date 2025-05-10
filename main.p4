#include <core.p4>
#include <v1model.p4>

// Ethernet header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    bit<8> data0;
    bit<8> data1;
    bit<8> data2;
    bit<8> data3;
    bit<8> data4;
    bit<8> data5;
    bit<8> data6;
    bit<8> data7;
    bit<8> data8;
    bit<8> data9;
    bit<8> data10;
    bit<8> data11;
    bit<8> data12;
    bit<8> data13;
    bit<8> data14;
    bit<8> data15;
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

// Ingress control
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action send_synack() {
        bit<48> tmp_mac;
        bit<32> tmp_ip;
        bit<16> tmp_port;

        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = 0x0a000002;
        hdr.ipv4.dstAddr = tmp_ip;

        tmp_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = 12345;
        hdr.tcp.dstPort = tmp_port;

        hdr.tcp.flags = 0x12;
    }

    action send_dummy_response() {
        bit<48> tmp_mac;
        bit<32> tmp_ip;
        bit<16> tmp_port;

        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = 0x0a000002;
        hdr.ipv4.dstAddr = tmp_ip;

        tmp_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = 12345;
        hdr.tcp.dstPort = tmp_port;

        hdr.tcp.flags = 0x18;

        hdr.payload.setValid();
        hdr.payload.data0  = 0x48; // H
        hdr.payload.data1  = 0x69; // i
        hdr.payload.data2  = 0x20; //  
        hdr.payload.data3  = 0x66; // f
        hdr.payload.data4  = 0x72; // r
        hdr.payload.data5  = 0x6f; // o
        hdr.payload.data6  = 0x6d; // m
        hdr.payload.data7  = 0x20; //  
        hdr.payload.data8  = 0x73; // s
        hdr.payload.data9  = 0x77; // w
        hdr.payload.data10 = 0x69; // i
        hdr.payload.data11 = 0x74; // t
        hdr.payload.data12 = 0x63; // c
        hdr.payload.data13 = 0x68; // h
        hdr.payload.data14 = 0x21; // !
        hdr.payload.data15 = 0x00; // \0
    }

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

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            tcp_table.apply();
        }
    }
}

// Egress (empty)
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// VerifyChecksum (empty)
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ComputeChecksum (empty)
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// Deparser
// Deparser
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.payload); // Ez CSAK AKKOR emitál, ha hdr.payload valid
    }
}

// V1Switch pipeline
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
