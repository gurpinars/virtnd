#ifndef VIRTND_IP_H
#define VIRTND_IP_H

#include <cstdint>
#include "ethernet.h"
#include "pk_buff.h"

static constexpr uint8_t IPv4 = 0x04;
static constexpr uint8_t IP_TCP = 0x06;
static constexpr uint8_t ICMPv4 = 0x01;

struct iphdr {
    uint8_t ihl:4;          /* Internet Header Length */
    uint8_t version:4;      /* Version */
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
    static IP* instance();
    IP(const IP &) = delete;
    IP &operator=(const IP &)= delete;
    void recv(pk_buff *, uint8_t*);
    void send(pk_buff *, uint8_t*);

private:
   IP(){};

};



extern IP *ip;
#endif //VIRTND_IP_H
