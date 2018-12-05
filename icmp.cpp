#include <iostream>
#include <cstring>
#include <netinet/in.h>
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


void ICMP::send(pk_buff *pkb, uint8_t type, uint8_t code) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);
    auto icmph = icmp_hdr(iph);

    // the first 64 bits of the original datagram's data
    uint8_t f64[8];
    memcpy(f64, icmph, 8);

    icmph->type = type;
    icmph->code = code;
    icmph->cksum = 0;

    if (type == TIME_EXCEEDED) {
        uint8_t *ptr = icmph->data;
        *ptr = 0x0000;

        memcpy(ptr + 4, iph, 4 * iph->ihl);
        memcpy(ptr + 24, f64, 8);

        iph->saddr = ntohl(iph->saddr);
        iph->daddr = ntohl(iph->daddr);
        iph->len = ntohs(iph->len);
        iph->id = ntohs(iph->id);

    }

    int icmp_len = iph->len - (4 * iph->ihl);
    icmph->cksum = checksum(icmph, icmp_len);

    ip->send(pkb, ICMPv4);

}

ICMP *icmp = ICMP::instance();