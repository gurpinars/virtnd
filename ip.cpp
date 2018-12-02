#include <iostream>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "utils.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "pk_buff.h"

/*
 * rfc 791
 * https://tools.ietf.org/html/rfc791
 */


IP *IP::instance() {
    static IP ins;
    return &ins;
}

void IP::recv(pk_buff *pkb) {

    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);

    if (iph->version != IPv4) {
        std::cerr << "Version is not IPv4\n";
        return;
    }

    if (pkb->len < sizeof(eth_frame) + sizeof(iphdr)) {
        std::cerr << "IPv4 packet is too small";
        return;
    }

    if (iph->ihl < 5) {
        std::cerr << "IPv4 header length must be at least 5\n";
        return;
    }

    if (iph->ihl * 4 != sizeof(iphdr)) {
        std::cerr << "IPv4 header is too small\n";
        return;
    }

    if (iph->ttl == 0) {
        std::cerr << "The Datagram must be destroyed\n";
        return;
    }

    auto cksum = checksum(iph, iph->ihl * 4);
    if (cksum != 0) {
        std::cerr << "IP Invalid Checksum\n";
        return;
    }

    iph->saddr = ntohl(iph->saddr);
    iph->daddr = ntohl(iph->daddr);
    iph->len = ntohs(iph->len);
    iph->id = ntohs(iph->id);

    switch (iph->pro) {
        case ICMPv4:
            icmp->recv(pkb);
            break;
        case IP_TCP:
            break;
        default:
            break;
    }
}

void IP::send(pk_buff *pkb) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);

    auto rt = route->lookup(ntohl(iph->saddr));
    if (!rt.gateway) {
        // dest unreach
        std::cerr << "route lookup fail\n";
        return;
    }

    pkb->rtdst = rt;

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

    if (rt.flags & RT_GATEWAY)
        iph->daddr = rt.gateway;

    auto c = arp->cache_lookup(iph->daddr);

    if (c.filled) {
        iph->len = htons(iph->len);
        iph->id = htons(iph->id);
        iph->daddr = htonl(iph->daddr);
        iph->saddr = htonl(iph->saddr);
        iph->cksum = htons(iph->cksum);
        iph->fragoff = htons(iph->fragoff);

        iph->cksum = checksum(iph, 4 * iph->ihl);
        ethn->send(pkb, c.hwaddr, pkb->hwaddr, pkb->len, ETH_P_IP);

    } else
        arp->request(pkb, iph->saddr, iph->daddr);

}

IP *ip = IP::instance();


