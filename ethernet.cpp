#include <netinet/in.h>
#include <cstring>
#include <linux/if_ether.h>
#include "ethernet.h"
#include "tap.h"


ETH *ETH::instance() {
    static ETH ins;
    return &ins;
}

void ETH::send(pk_buff *pkb,
               const uint8_t *dst_hwaddr,
               const uint8_t *hwaddr,
               ssize_t len,
               uint16_t type) {

    auto eth = eth_hdr(pkb->data);
    eth->type = htons(type);
    memcpy(eth->dmac, dst_hwaddr, 6);
    memcpy(eth->smac, hwaddr, 6);

    tapd->write(pkb->data, len);

}

ETH *ethn = ETH::instance();
