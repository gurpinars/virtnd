#ifndef VIRTND_NETDEV_H
#define VIRTND_NETDEV_H

#include <cstdint>
#include <memory>
#include "arp.h"
#include "ip.h"


extern TAPDev *tapd;

class NetDev {
public:
    NetDev(const char *, const char *);
    ~NetDev() { close(epoll_fd); }
    void loop();

private:
    uint32_t addr;
    uint8_t hwaddr[6];
    ARP arp;
    IP ip;
    int epoll_fd;

};

#endif //VIRTND_NETDEV_H
