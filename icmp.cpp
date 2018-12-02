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

static constexpr uint8_t ECHO_REPLY = 0x00;
static constexpr uint8_t DST_UNREACHABLE = 0x03;
static constexpr uint8_t SRC_QUENCH = 0x04;
static constexpr uint8_t REDIRECT = 0x05;
static constexpr uint8_t ECHO_REQUEST = 0x08;
static constexpr uint8_t ROUTER_ADV = 0x09;
static constexpr uint8_t ROUTER_SOL = 0x0a;
static constexpr uint8_t TIMEOUT = 0x0b;
static constexpr uint8_t MALFORMED = 0x0c;

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
            std::cout << "Got 1 ECHO request\n";
            reply(pkb);
            break;
        default:
            break;
    }

}

void ICMP::reply(pk_buff *pkb) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);
    auto icmph = icmp_hdr(iph);

    int icmp_len = iph->len - (iph->ihl * 4);
    icmph->type = ECHO_REPLY;
    icmph->code = 0x00;
    icmph->cksum = 0;
    icmph->cksum = checksum(icmph, icmp_len);

    std::cout << "Sent 1 ECHO Reply\n";
    ip->send(pkb);
}


ICMP *icmp = ICMP::instance();