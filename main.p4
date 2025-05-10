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
            default: accept;
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

// Egy 32 bites szekvencia-szám tárolására
register<bit<32>>(1) seq_register;

// Ingress control
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 256;
    }

    action send_synack() {
        bit<48> tmp_mac;
        bit<32> tmp_ip;
        bit<16> tmp_port;
        bit<32> client_seq;

        client_seq = hdr.tcp.seqNo; // Mentsük el a kliens seq számát

        // Ethernet címek csere
        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        // IP-címek csere
        tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = 0x0a000002;
        hdr.ipv4.dstAddr = tmp_ip;

        // Portok csere
        tmp_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = 9090;
        hdr.tcp.dstPort = tmp_port;

        // TCP zászlók beállítása (SYN+ACK)
        hdr.tcp.flags = 0x12;

        // Szekvenciaszám lekérdezése és beállítása
        bit<32> seq;
        seq_register.read(seq, 0);
        hdr.tcp.seqNo = seq;

        // ACK szám a kliens SYN-jére válaszolva
        hdr.tcp.ackNo = client_seq + 1;

        // Kötelező mezők frissítése
        hdr.tcp.dataOffset = 5;
        hdr.ipv4.totalLen = 20 + 20; // IPv4 + TCP
        hdr.ipv4.ttl = 64;

        // Regiszter frissítése
        seq = seq + 1;
        seq_register.write(0, seq);
    }

    action send_dummy_response() {
        bit<48> tmp_mac;
        bit<32> tmp_ip;
        bit<16> tmp_port;
        bit<32> client_seq;
        bit<32> client_ack;

        client_seq = hdr.tcp.seqNo; // Mentsük el a kliens seq számát
        client_ack = hdr.tcp.ackNo;

        // Ethernet címek csere
        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        // IP-címek csere
        tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = 0x0a000002;
        hdr.ipv4.dstAddr = tmp_ip;

        // Portok csere
        tmp_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = 9090;
        hdr.tcp.dstPort = tmp_port;

        hdr.tcp.flags = 0x18;  // PSH+ACK

        // Dummy válasz szekvenciaszám: folytatásként olvassuk a regiszterből
        bit<32> seq;
        seq_register.read(seq, 0);
        hdr.tcp.seqNo = seq;
        seq = seq + 1;
        seq_register.write(0, seq);

        // ACK szám: az adat utolsó byte-jára válaszolunk
        hdr.tcp.ackNo = client_seq + 1; // Feltételezve, hogy 1 byte-nyi adat jött

        // Kötelező mezők frissítése
        hdr.tcp.dataOffset = 5;
        hdr.ipv4.totalLen = 20 + 20 + 16; // IPv4 + TCP + Payload
        hdr.ipv4.ttl = 64;

        // Dummy payload
        hdr.payload.setValid();
        hdr.payload.data0 = 0x48;  // "H"
        hdr.payload.data1 = 0x69;  // i
        hdr.payload.data2 = 0x20;  //  
        hdr.payload.data3 = 0x66;  // f
        hdr.payload.data4 = 0x72;  // r
        hdr.payload.data5 = 0x6f;  // o
        hdr.payload.data6 = 0x6d;  // m
        hdr.payload.data7 = 0x20;  //  
        hdr.payload.data8 = 0x73;  // s
        hdr.payload.data9 = 0x77;  // w
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
        dmac.apply();  // Ez elengedhetetlen!
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

// ✅ ComputeChecksum – IPv4 és TCP checksum kiszámítása
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,                 // reserved
                8w6,                 // protocol = TCP
                16w20,              // TCP header length in bytes (assuming no options)
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
    }
}


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
