#ifndef VIRTND_ROUTE_H
#define VIRTND_ROUTE_H

#include <cstdint>
#include <vector>

static constexpr uint8_t RT_LOOPBACK = 0x01;
static constexpr uint8_t RT_GATEWAY = 0x02;
static constexpr uint8_t RT_HOST   =  0x04;

struct rtentry {
    uint32_t dst;
    uint32_t gateway;
    uint32_t netmask;
    uint8_t flags;
    uint32_t metric;
};

class ROUTE {
public:
    static ROUTE *instance();
    ROUTE(const ROUTE &) = delete;
    ROUTE &operator=(const ROUTE &)= delete;
    rtentry &lookup(uint32_t);

private:
    ROUTE();
    std::vector<rtentry> rt_list;

};

extern ROUTE *route;
#endif //VIRTND_ROUTE_H
