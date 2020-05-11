#ifndef VIRTND_ETHERNET_H
#define VIRTND_ETHERNET_H

#include <cstdint>
#include "pk_buff.h"

static constexpr uint16_t ETH_P_ARP = 0x0806;
static constexpr uint16_t ETH_P_IP = 0x0800;

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

    ETH &operator=(const ETH &) = delete;

    static void xmit(pk_buff &&pkb,
                     const uint8_t *dst_hwaddr,
                     const uint8_t *hwaddr,
                     ssize_t len,
                     uint16_t type);

private:
    ETH() = default;;
};

inline struct eth_frame *eth_hdr(void *buf) {
    return reinterpret_cast<eth_frame *>(buf);
}

#define _ETH() ETH::instance()

#endif //VIRTND_ETHERNET_H
