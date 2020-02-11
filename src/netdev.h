#ifndef VIRTND_NETDEV_H
#define VIRTND_NETDEV_H

#include <cstdint>
#include <unistd.h>
#include "pk_buff.h"
#include "observer.hpp"


class NetDev: public Subject<pk_buff&&> {
public:
    NetDev(const char *addr, const char *hwaddr);
    ~NetDev();
    void loop();

private:
    uint32_t addr;
    uint8_t hwaddr[6];
    int epoll_fd;

};

#endif //VIRTND_NETDEV_H
