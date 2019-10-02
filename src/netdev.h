#ifndef VIRTND_NETDEV_H
#define VIRTND_NETDEV_H

#include <cstdint>
#include <unistd.h>
#include "pk_buff.h"


class NetDev {
public:
    NetDev(const char *, const char *);
    ~NetDev();
    void loop();

private:
    uint32_t addr;
    uint8_t hwaddr[6];
    int epoll_fd;
    pk_buff *pkb;

};

#endif //VIRTND_NETDEV_H
