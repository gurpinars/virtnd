#ifndef VIRTND_IP_H
#define VIRTND_IP_H

#include <cstdint>
#include "ethernet.h"
#include "pk_buff.h"

static constexpr uint8_t IPv4 = 0x04;
static constexpr uint8_t ICMPv4 = 0x01;

#define MIN_IP_HDR_SZ 20
#define IP_HDR_SZ(iph) (4 * (iph)->ihl)

namespace IPUtils {

uint16_t checksum(void *addr, int count);

}

struct iphdr {
    uint8_t ihl: 4;          /* Internet Header Length */
    uint8_t version: 4;      /* Version */
    uint8_t tos;            /* Type of Service */
    uint16_t len;           /* Total Length */
    uint16_t id;            /* Identification */
    uint16_t fragoff;       /* Fragment Offset */
    uint8_t ttl;            /* Time to Live */
    uint8_t pro;            /* Protocol */
    uint16_t cksum;         /* Header Checksum */
    uint32_t saddr;         /* Source Address */
    uint32_t daddr;         /* Destination Address */
    uint8_t data[];
} __attribute__((packed));

inline struct iphdr *ip_hdr(struct eth_frame *eth) {
    return reinterpret_cast<iphdr *>(eth->payload);
}

class IP {
public:
    static IP *instance();

    IP(const IP &) = delete;

    IP &operator=(const IP &) = delete;

    static void recv(pk_buff &&pkb);

    static void send(pk_buff &&pkb, uint8_t pro);

private:
    IP() = default;;

    static void forward(pk_buff &&pkb);

    static void send_out(pk_buff &&pkb, uint8_t *hwaddr);

    static void check_opts(iphdr *iph);

};


#define _IP() IP::instance()

#endif //VIRTND_IP_H
