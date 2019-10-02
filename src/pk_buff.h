#ifndef VIRTND_PK_BUFF_H
#define VIRTND_PK_BUFF_H

#include "route.h"
static constexpr uint32_t MTU = 1500;

typedef struct {
    ssize_t len;
    uint8_t data[MTU];
    uint8_t dev_hwaddr[6];
    uint32_t dev_addr;
    rtentry rtdst;

} pk_buff;

#endif //VIRTND_PK_BUFF_H
