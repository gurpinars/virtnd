#ifndef VIRTND_ICMP_H
#define VIRTND_ICMP_H

#include <cstdint>
#include "ethernet.h"
#include "pk_buff.h"


class ICMP {
public:
    static ICMP *instance();
    ICMP(const ICMP &) = delete;
    ICMP &operator=(const ICMP &)= delete;
    void recv(pk_buff *, uint8_t[]);
    void reply(pk_buff *, uint8_t[]);

private:
    ICMP() {};

    struct icmp {
        uint8_t type;
        uint8_t code;
        uint16_t cksum;
        uint8_t data[];
    } __attribute__((packed));

    struct icmp_echo {
        uint16_t id;
        uint16_t seq;
        uint8_t data[];
    } __attribute__((packed));

    struct icmp_dst_unreachable {
        uint8_t unused;
        uint8_t len;
        uint16_t var;
        uint8_t data[];
    } __attribute__((packed));


};

extern ICMP *icmp;
#endif //VIRTND_ICMP_H
