#ifndef VIRTND_PK_BUFF_H
#define VIRTND_PK_BUFF_H

#include "route.h"

typedef struct {
    ssize_t len;
    uint8_t *data;
    rtentry rtdst;

} pk_buff;

#endif //VIRTND_PK_BUFF_H
