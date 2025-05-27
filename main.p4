#include <core.p4>
#include <v1model.p4>

// ========== Header definíciók ==========
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

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
    bit<8> data16;
    bit<8> data17;
    bit<8> data18;
    bit<8> data19;
    bit<8> data20;
    bit<8> data21;
    bit<8> data22;
    bit<8> data23;
    bit<8> data24;
    bit<8> data25;
    bit<8> data26;
    bit<8> data27;
    bit<8> data28;
    bit<8> data29;
    bit<8> data30;
    bit<8> data31;
    bit<8> data32;
    bit<8> data33;
    bit<8> data34;
    bit<8> data35;
    bit<8> data36;
}

// ========== Header struktúrák ==========
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    payload_t  payload;
}

struct metadata_t {}

// ========== Parser ==========
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

// ========== Egy 32 bites regiszter a szekvenciaszámhoz ==========
register<bit<32>>(1) seq_register;
register<bit<16>>(1) id_register;

// ========== Ingress logika ==========
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

    // == SYN-ACK válasz ==
    action send_synack() {
        bit<48> tmp_mac;
        bit<32> tmp_ip;
        bit<16> tmp_port;
        bit<32> client_seq;
        bit<16> id_val;

        client_seq = hdr.tcp.seqNo;

        // MAC címek felcserélése
        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        // IP címek felcserélése
        tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp_ip;

        // TCP portok felcserélése
        tmp_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = tmp_port;

        // Csak SYN-re: elmentjük a kliens SYN seq-t
        seq_register.write(0, client_seq);

        // Szerver seqNo: a most elmentett érték
        hdr.tcp.seqNo = client_seq;

        // ACK mező: kliens seq + 1
        hdr.tcp.ackNo = client_seq + 1;

        hdr.tcp.flags = 0x12; // SYN+ACK
        hdr.tcp.dataOffset = 5;
        hdr.tcp.reserved = 0;
        hdr.tcp.window = 8192;
        hdr.tcp.urgentPtr = 0;

        // IP header frissítése
        hdr.ipv4.ttl = 64;
        hdr.ipv4.totalLen = 20 + 20; // IP + TCP header

        // Identification mező növelése
        id_register.read(id_val, 0);
        hdr.ipv4.identification = id_val;
        id_register.write(0, id_val + 1);

        // Regiszter érték növelése (mindig!)
        seq_register.write(0, client_seq + 1);

        // Kimeneti port
        standard_metadata.egress_spec = 1;
    }

    // == Dummy PSH+ACK válasz ==
    action send_dummy_response() {
        bit<48> tmp_mac;
        bit<32> tmp_ip;
        bit<16> tmp_port;
        bit<32> seq;
        bit<16> id_val;
        bit<32> client_seq;

        client_seq = hdr.tcp.seqNo;

        // MAC címek felcserélése
        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        // IP címek felcserélése
        tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp_ip;

        // TCP portok felcserélése
        tmp_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = tmp_port;

        // Szerver seqNo kiolvasása
        seq_register.read(seq, 0);
        hdr.tcp.seqNo = seq;

        // ACK: kliens seq + 1
        hdr.tcp.ackNo = client_seq + 1;

        hdr.tcp.flags = 0x18; // PSH+ACK
        hdr.tcp.dataOffset = 5;
        hdr.tcp.reserved = 0;
        hdr.tcp.window = 8192;
        hdr.tcp.urgentPtr = 0;

        // IP header
        hdr.ipv4.ttl = 64;
        hdr.ipv4.totalLen = 20 + 20 + 37;

        // Identification mező növelése
        id_register.read(id_val, 0);
        hdr.ipv4.identification = id_val;
        id_register.write(0, id_val + 1);

        // Payload aktiválása
        hdr.payload.setValid();
        hdr.payload.data0 = 0x48;  // 'H'
        hdr.payload.data1 = 0x69;  // 'i'
        hdr.payload.data2 = 0x20;  // ' '
        hdr.payload.data3 = 0x66;  // 'f'
        hdr.payload.data4 = 0x72;  // 'r'
        hdr.payload.data5 = 0x6f;  // 'o'
        hdr.payload.data6 = 0x6d;  // 'm'
        hdr.payload.data7 = 0x20;  // ' '
        hdr.payload.data8 = 0x73;  // 's'
        hdr.payload.data9 = 0x77;  // 'w'
        hdr.payload.data10 = 0x69; // 'i'
        hdr.payload.data11 = 0x74; // 't'
        hdr.payload.data12 = 0x63; // 'c'
        hdr.payload.data13 = 0x68; // 'h'
        hdr.payload.data14 = 0x21; // '!'
        hdr.payload.data15 = 0x20; // ' '

        hdr.payload.data16 = 0x54; // 'T'
        hdr.payload.data17 = 0x68; // 'h'
        hdr.payload.data18 = 0x69; // 'i'
        hdr.payload.data19 = 0x73; // 's'
        hdr.payload.data20 = 0x20; // ' '
        hdr.payload.data21 = 0x69; // 'i'
        hdr.payload.data22 = 0x73; // 's'
        hdr.payload.data23 = 0x20; // ' '
        hdr.payload.data24 = 0x74; // 't'
        hdr.payload.data25 = 0x68; // 'h'
        hdr.payload.data26 = 0x65; // 'e'
        hdr.payload.data27 = 0x20; // ''
        hdr.payload.data28 = 0x70; // 'p'
        hdr.payload.data29 = 0x61; // 'a'
        hdr.payload.data30 = 0x79; // 'y'
        hdr.payload.data31 = 0x6C; // 'l'
        hdr.payload.data32 = 0x6F; // 'o'
        hdr.payload.data33 = 0x61; // 'a'
        hdr.payload.data34 = 0x64; // 'd'
        hdr.payload.data35 = 0x21; // '!'
        hdr.payload.data36 = 0x00; // '\0'

        // Szekvenciaszám növelése eggyel
        seq_register.write(0, seq + 1);

        standard_metadata.egress_spec = 1;
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
        default_action = NoAction();
    }

    action drop() {
        mark_to_drop(standard_metadata);
        standard_metadata.egress_spec = 0;
    }

    apply {
        if (hdr.tcp.isValid()) {
            tcp_table.apply();
        } else {
            dmac.apply();
        }
    }
}

// ========== Egress (nem módosítunk semmit) ==========
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// ========== Checksum ellenőrzés (nem használt) ==========
control MyVerifyChecksum(inout headers_t hdr,
                         inout metadata_t meta) {
    apply { }
}

// ========== Checksum újraszámítás ==========
control MyComputeChecksum(inout headers_t hdr,
                          inout metadata_t meta) {
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

        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.payload.isValid(),
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, 8w6 },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );

        update_checksum(
            hdr.tcp.isValid() && !hdr.payload.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                8w6,
                16w20,
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

// ========== Deparser ==========
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.payload);
    }
}

// ========== Pipeline összeállítása ==========
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
