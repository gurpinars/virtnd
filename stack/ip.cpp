#include <iostream>
#include <cstring>
#include <bitset>
#include "ip.h"
#include "ethernet.h"
#include "icmp.h"
#include "arp.h"
#include "in.hpp"
#include "pk_buff.h"

/*
 * rfc 791
 * https://tools.ietf.org/html/rfc791
 */


/* IP Options */
namespace IPOptions {

static constexpr uint8_t EOOL = 0x0;
static constexpr uint8_t NOP = 0x1;
static constexpr uint8_t SEC = 0x82;
static constexpr uint8_t LSRR = 0x83;
static constexpr uint8_t SSRR = 0x89;
static constexpr uint8_t RR = 0x7;
static constexpr uint8_t SID = 0x88;
static constexpr uint8_t TS = 0x44;

}


IP *IP::instance() {
    static IP ins;
    return &ins;
}

void IP::recv(pk_buff &&pkb) {
    auto eth = eth_hdr(pkb.data);
    auto iph = ip_hdr(eth);

    if (iph->version != IPv4) {
        std::cerr << "Version is not IPv4\n";
        return;
    }

    if (pkb.len < sizeof(eth_frame) + sizeof(iphdr)) {
        std::cerr << "IPv4 packet is too small";
        return;
    }

    if (iph->ihl < 5) {
        std::cerr << "IPv4 header length must be at least 5\n";
        return;
    }

    if (IP_HDR_SZ(iph) < sizeof(iphdr)) {
        std::cerr << "IPv4 header is too small\n";
        return;
    }

    if (iph->ttl == 0) {
        std::cerr << "Ip TTL is 0\n";
        _ICMP()->send(std::move(pkb), TIME_EXCEEDED, 0x00);
        return;
    }

    auto cksum = IPUtils::checksum(iph, IP_HDR_SZ(iph));
    if (cksum != 0) {
        std::cerr << "IP Invalid Checksum\n";
        return;
    }


    iph->saddr = stack::in::ntohl(iph->saddr);
    iph->daddr = stack::in::ntohl(iph->daddr);
    iph->len = stack::in::ntohs(iph->len);

    if (iph->ihl > 5)
        check_opts(iph);

    rtentry rt = _ROUTE()->lookup(iph->daddr);
    pkb.rtdst = std::move(rt);

    /* Is this packet for us */
    if (pkb.rtdst.m_flags & RT_HOST) {
        switch (iph->pro) {
            case ICMPv4:
                _ICMP()->recv(std::move(pkb));
                break;
            default:
                break;
        }
    } else
        forward(std::move(pkb));

}

void IP::send(pk_buff &&pkb, uint8_t pro) {
    auto eth = eth_hdr(pkb.data);
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

    if (pkb.rtdst.m_flags & RT_LOOPBACK) {
        std::cout << "To loopback\n";
        send_out(std::move(pkb), pkb.dev_hwaddr);
        return;
    }

    if (pkb.rtdst.m_flags & RT_GATEWAY)
        iph->daddr = pkb.rtdst.m_gateway;

    auto found = _ARP()->cache_lookup(iph->daddr);
    if (found)
        send_out(std::move(pkb), found.hwaddr);
    else
        _ARP()->request(std::move(pkb), iph->saddr, iph->daddr);

}


void IP::forward(pk_buff &&pkb) {
    auto eth = eth_hdr(pkb.data);
    auto iph = ip_hdr(eth);

    iph->saddr = stack::in::htonl(iph->saddr);
    iph->daddr = stack::in::htonl(iph->daddr);
    iph->len = stack::in::htons(iph->len);

    if (iph->ttl <= 1) {
        _ICMP()->send(std::move(pkb), TIME_EXCEEDED, 0x00);
        return;
    }

    iph->ttl--;

    if ((pkb.rtdst.m_flags & RT_GATEWAY) || pkb.rtdst.m_metric > 0)
        iph->daddr = pkb.rtdst.m_gateway;

    std::cout << "Forwarding\n";
    send(std::move(pkb), iph->pro);

}


void IP::send_out(pk_buff &&pkb, uint8_t *hwaddr) {
    auto eth = eth_hdr(pkb.data);
    auto iph = ip_hdr(eth);

    iph->len = stack::in::htons(iph->len);
    iph->daddr = stack::in::htonl(iph->daddr);
    iph->saddr = stack::in::htonl(iph->saddr);
    iph->fragoff = stack::in::htons(iph->fragoff);

    iph->cksum = IPUtils::checksum(iph, IP_HDR_SZ(iph));
    _ETH()->xmit(std::move(pkb), hwaddr, pkb.dev_hwaddr, pkb.len, ETH_P_IP);
}


void IP::check_opts(iphdr *iph) {
    int opts_count = IP_HDR_SZ(iph) - MIN_IP_HDR_SZ;
    auto *options = reinterpret_cast<uint8_t *>(iph->data);

    for (int i = 0; i < opts_count; ++i) {
        switch (*(options + i) & 0xffu) {
            case IPOptions::LSRR: {
                uint8_t dst[4];
                memcpy(dst, (options + i) + 3, 4);

                auto dst0 = std::bitset<8>(dst[0]).to_string();
                auto dst1 = std::bitset<8>(dst[1]).to_string();
                auto dst2 = std::bitset<8>(dst[2]).to_string();
                auto dst3 = std::bitset<8>(dst[3]).to_string();
                auto bf = dst0.append(dst1).append(dst2).append(dst3);

                iph->daddr = std::bitset<32>(bf).to_ulong();
                break;
            }
            case IPOptions::EOOL:
            case IPOptions::NOP:
            case IPOptions::SEC:
            case IPOptions::SSRR:
            case IPOptions::RR:
            case IPOptions::SID:
            case IPOptions::TS:
            default:
                break;
        }
    }
}

namespace IPUtils {

uint16_t checksum(void *addr, int count) {

    /* Compute Internet Checksum for "count" bytes
     *    beginning at location "addr".
     *    https://tools.ietf.org/html/rfc1071
     */

    uint32_t sum = 0;

    auto *ptr_16 = static_cast<uint16_t *>(addr);

    for (; count > 1; count -= 2) {
        // This is the inner loop
        sum += *ptr_16++;
    }

    // Add left-over byte, if any
    if (count > 0)
        sum += *static_cast<uint8_t *>(addr);

    // Fold 32-bit sum to 16 bits
    while (sum >> 16u)
        sum = (sum & 0xffffu) + (sum >> 16u);

    return ~sum;
}
}

