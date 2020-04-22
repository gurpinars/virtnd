#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include "ip.h"
#include "icmp.h"
#include "utils.h"
#include "arp.h"
#include "pk_buff.h"

/*
 * rfc 792
 * https://tools.ietf.org/html/rfc792
 */

#define ALLOC_ICMP_PKB(iph) (reinterpret_cast<icmp *>((iph)->data))


ICMP *ICMP::instance() {
    static ICMP ins;
    return &ins;
}


void ICMP::recv(pk_buff &&pkb) {
    auto eth = eth_hdr(pkb.data);
    auto iph = ip_hdr(eth);
    auto icmph = icmp_hdr(iph);

    int icmp_len = iph->len - IP_HDR_SZ(iph);

    auto cksum = checksum(icmph, icmp_len);
    if (cksum != 0) {
        std::cerr << "ICMP Invalid Checksum\n";
        return;
    }

    switch (icmph->type) {
        case ECHO_REQUEST:
            std::cout << "ICMP ECHO REQUEST message received\n";
            send(std::move(pkb), ECHO_REPLY, 0x00);
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


void ICMP::send(pk_buff &&pkb, uint8_t type, uint8_t code) {
    auto eth = eth_hdr(pkb.data);
    auto iph = ip_hdr(eth);
    auto icmph = icmp_hdr(iph);

    // the first 64 bits of the original datagram's data
    uint8_t f64[8];
    memcpy(f64, icmph, 8);

    // Internet Header
    uint8_t iphdr[IP_HDR_SZ(iph)];
    memcpy(iphdr, iph, IP_HDR_SZ(iph));

    icmph = ALLOC_ICMP_PKB(iph);
    icmph->type = type;
    icmph->code = code;
    icmph->cksum = 0;

    if (type == TIME_EXCEEDED) {
        uint8_t *ptr = icmph->data;
        *ptr = 0x0000;

        memcpy(ptr + 4, iphdr, IP_HDR_SZ(iph));
        memcpy(ptr + 4 + IP_HDR_SZ(iph), f64, 8);

        iph->saddr = ntohl(iph->saddr);
        iph->daddr = pkb.dev_addr;
        iph->len = ntohs(iph->len);
    }

    int icmp_len = iph->len - MIN_IP_HDR_SZ;
    icmph->cksum = checksum(icmph, icmp_len);

    _IP()->send(std::move(pkb), ICMPv4);

}
