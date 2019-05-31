#ifndef VIRTND_ETHERNET_H
#define VIRTND_ETHERNET_H

#include <cstdint>
#include "pk_buff.h"

struct eth_frame {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
    uint8_t payload[];
} __attribute__((packed));

class ETH {
public:
    static ETH *instance();
    ETH(const ETH &) = delete;
    ETH &operator=(const ETH &)= delete;

    void xmit(pk_buff *, const uint8_t*, const uint8_t*, ssize_t, uint16_t);

private:
    ETH() {};
};

inline struct eth_frame *eth_hdr(void *buf) {
    return reinterpret_cast<eth_frame *>(buf);
}

extern ETH *ethn;

#endif //VIRTND_ETHERNET_H
