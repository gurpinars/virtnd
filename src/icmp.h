#ifndef VIRTND_ICMP_H
#define VIRTND_ICMP_H

#include <cstdint>
#include "pk_buff.h"

static constexpr uint8_t ECHO_REPLY = 0x00;
static constexpr uint8_t DST_UNREACHABLE = 0x03;
static constexpr uint8_t ECHO_REQUEST = 0x08;
static constexpr uint8_t TIME_EXCEEDED = 0x0b;
static constexpr uint8_t MALFORMED = 0x0c;


class ICMP {
public:
    static ICMP *instance();
    ICMP(const ICMP &) = delete;
    ICMP &operator=(const ICMP &)= delete;
    void recv(pk_buff *);
    void send(pk_buff *, uint8_t, uint8_t);

private:
    ICMP() {};

    struct icmp {
        uint8_t type;
        uint8_t code;
        uint16_t cksum;
        uint8_t data[];
    } __attribute__((packed));

    inline struct icmp *icmp_hdr(struct iphdr *iph) {
        int offset = IP_HDR_SZ(iph) - MIN_IP_HDR_SZ;
        return reinterpret_cast<icmp *>(iph->data + offset);
    }


};


extern ICMP *icmp;
#endif //VIRTND_ICMP_H
