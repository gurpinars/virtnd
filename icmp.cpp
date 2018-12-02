#include <iostream>
#include <cstring>
#include "ip.h"
#include "icmp.h"
#include "utils.h"
#include "arp.h"

/*
 * rfc 792
 * https://tools.ietf.org/html/rfc792
 */


ICMP *ICMP::instance() {
    static ICMP ins;
    return &ins;
}


void ICMP::recv(pk_buff *pkb) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);
    auto icmph = icmp_hdr(iph);

    int icmp_len = iph->len - (iph->ihl * 4);

    auto cksum = checksum(icmph, icmp_len);
    if (cksum != 0) {
        std::cerr << "ICMP Invalid Checksum\n";
        return;
    }

    switch (icmph->type) {
        case ECHO_REQUEST:
            std::cout << "ICMP ECHO REQUEST message received\n";
            send(pkb, ECHO_REPLY, 0x00);
            break;
        case ECHO_REPLY:
            std::cout << "ICMP ECHO REPLY message received\n";
            break;
        case DST_UNREACHABLE:
            std::cout << "ICMP DESTINATION UNREACHABLE message received\n";
            break;
        case TIME_EXCEEDED:
            std::cout << "ICMP TIME EXCEEDED message received\n";
            break;
        default:
            break;
    }

}


void ICMP::send(pk_buff *pkb, uint8_t type,uint8_t code) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);
    auto icmph = icmp_hdr(iph);

    int icmp_len = iph->len - (iph->ihl * 4);

    icmph->type = type;
    icmph->code = code;
    icmph->cksum = 0;
    icmph->cksum = checksum(icmph, icmp_len);

    ip->send(pkb, ICMPv4);

}

ICMP *icmp = ICMP::instance();