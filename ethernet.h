#ifndef TCP_IP_ETHERNET_H
#define TCP_IP_ETHERNET_H

#include <cstdint>

struct eth_frame {
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t type;
    uint8_t  payload[];
} __attribute__((packed));


inline struct eth_frame *eth_hdr(void *buf) {
    return reinterpret_cast<eth_frame *>(buf);
}

#endif //TCP_IP_ETHERNET_H
