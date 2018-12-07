#include <iostream>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "utils.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"

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
        std::cerr << "Ip TTL is 0\n";
        icmp->send(pkb, TIME_EXCEEDED, 0x00);
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

    auto rt = route->lookup(iph->daddr);
    pkb->rtdst = rt;

    // Is this packet for us
    if (rt.flags & RT_HOST) {
        switch (iph->pro) {
            case ICMPv4:
                icmp->recv(pkb);
                break;
            case IP_TCP:
                break;
            case IP_UDP:
                break;
            default:
                break;
        }
    } else
        forward(pkb);

}

void IP::send(pk_buff *pkb, uint8_t pro) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);

    // fill header info
    iph->version = IPv4;
    iph->ihl = 0x05;
    iph->tos = 0;
    iph->fragoff = 0x4000;
    iph->ttl = 64;
    iph->pro = pro;
    iph->cksum = 0;

    // swap saddr,daddr
    iph->saddr ^= iph->daddr;
    iph->daddr ^= iph->saddr;
    iph->saddr ^= iph->daddr;

    if (pkb->rtdst.flags & RT_LOOPBACK) {
        std::cout << "To loopback\n";
        send_out(pkb, pkb->hwaddr);
        return;
    }

    if (pkb->rtdst.flags & RT_GATEWAY)
        iph->daddr = pkb->rtdst.gateway;

    auto c = arp->cache_lookup(iph->daddr);
    if (c.filled)
        send_out(pkb, c.hwaddr);
    else
        arp->request(pkb, iph->saddr, iph->daddr);

}

void IP::forward(pk_buff *pkb) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);

    if (iph->ttl <= 1) {
        icmp->send(pkb, TIME_EXCEEDED, 0x00);
        return;
    }

    iph->ttl--;

    if ((pkb->rtdst.flags & RT_GATEWAY) || pkb->rtdst.metric > 0)
        iph->daddr = pkb->rtdst.gateway;

    send(pkb, iph->pro);

}

void IP::send_out(pk_buff *pkb, uint8_t *hwaddr) {
    auto eth = eth_hdr(pkb->data);
    auto iph = ip_hdr(eth);

    iph->len = htons(iph->len);
    iph->daddr = htonl(iph->daddr);
    iph->saddr = htonl(iph->saddr);
    iph->fragoff = htons(iph->fragoff);

    iph->cksum = checksum(iph, 4 * iph->ihl);
    ethn->xmit(pkb, hwaddr, pkb->hwaddr, pkb->len, ETH_P_IP);
}

IP *ip = IP::instance();


