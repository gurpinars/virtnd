#include <iostream>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <cstring>
#include "ip.h"
#include "icmp.h"
#include "utils.h"
#include "arp.h"
#include "tap.h"

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


void ICMP::recv(pk_buff *pkb, uint8_t hwaddr[]) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);
    auto icmph =icmp_hdr(iph);

    int icmp_len = iph->len - (iph->ihl * 4);

    auto cksum = checksum(icmph, icmp_len);
    if (cksum != 0) {
        std::cerr << "ICMP Invalid Checksum\n";
        return;
    }

    switch (icmph->type) {
        case ECHO_REQUEST:
            std::cout << "Got 1 ECHO request\n";
            reply(pkb, hwaddr);
            break;
        default:
            break;
    }

}

void ICMP::reply(pk_buff *pkb, uint8_t hwaddr[]) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);
    auto icmph =icmp_hdr(iph);

    int icmp_len = iph->len - (iph->ihl * 4);
    icmph->type = ECHO_REPLY;
    icmph->code = 0x00;
    icmph->cksum = 0;
    icmph->cksum = checksum(icmph, icmp_len);

    iph->version = IPv4;
    iph->ihl = 0x05;
    iph->tos = 0;
    iph->fragoff = 0x4000;
    iph->ttl = 64;
    iph->pro = ICMPv4;
    iph->cksum = 0;

    // swap saddr,daddr
    iph->saddr ^= iph->daddr;
    iph->daddr ^= iph->saddr;
    iph->saddr ^= iph->daddr;

    if (pkb->rtdst.flags & RT_GATEWAY)
        iph->daddr = pkb->rtdst.gateway;


    auto c = arp->cache_lookup(iph->daddr);
    if (c.pro) {
        iph->len = htons(iph->len);
        iph->id = htons(iph->id);
        iph->daddr = htonl(iph->daddr);
        iph->saddr = htonl(iph->saddr);
        iph->cksum = htons(iph->cksum);
        iph->fragoff = htons(iph->fragoff);

        iph->cksum = checksum(iph, 4 * iph->ihl);

        eth->type = htons(ETH_P_IP);
        memcpy(eth->dmac, c.hwaddr, 6);
        memcpy(eth->smac, hwaddr, 6);

        std::cout << "Sent 1 ECHO reply\n";
        tapd->write(pkb->data, pkb->len);
    } else
        arp->request(pkb, iph->saddr, hwaddr, iph->daddr);
}


ICMP *icmp = ICMP::instance();