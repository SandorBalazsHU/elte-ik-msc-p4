action send_synack() {
    // Swap addresses
    modify_field(hdr.ethernet.dstAddr, hdr.ethernet.srcAddr);
    modify_field(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);

    modify_field(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr);
    modify_field(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);

    modify_field(hdr.tcp.dstPort, hdr.tcp.srcPort);
    modify_field(hdr.tcp.srcPort, 12345); // server port

    // Set flags to SYN + ACK
    modify_field(hdr.tcp.flags, 0x12);

    // Update TCP header (you can later add seq/ack numbers)
}

action send_dummy_response() {
    modify_field(hdr.ethernet.dstAddr, hdr.ethernet.srcAddr);
    modify_field(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);

    modify_field(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr);
    modify_field(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);

    modify_field(hdr.tcp.dstPort, hdr.tcp.srcPort);
    modify_field(hdr.tcp.srcPort, 12345);

    // TCP flags: PSH + ACK
    modify_field(hdr.tcp.flags, 0x18);
    // Dummy response, no payload in this version
}

action nop() { }
