#ifndef VIRTND_ROUTE_H
#define VIRTND_ROUTE_H

#include <cstdint>
#include <vector>

static constexpr uint8_t RT_LOOPBACK = 0x01;
static constexpr uint8_t RT_GATEWAY = 0x02;
static constexpr uint8_t RT_HOST = 0x04;

struct rtentry {
    rtentry() = default;

    rtentry(uint32_t dst, uint32_t gateway, uint32_t netmask, uint8_t flags, uint32_t metric) :
            m_dst(dst),
            m_gateway(gateway),
            m_netmask(netmask),
            m_flags(flags),
            m_metric(metric) {}

    rtentry(const rtentry &other) {
        m_dst = other.m_dst;
        m_gateway = other.m_gateway;
        m_netmask = other.m_netmask;
        m_flags = other.m_flags;
        m_metric = other.m_metric;
    }

    rtentry &operator=(const rtentry &other) noexcept {
        if (this != &other) {
            m_dst = other.m_dst;
            m_gateway = other.m_gateway;
            m_netmask = other.m_netmask;
            m_flags = other.m_flags;
            m_metric = other.m_metric;
        }

        return *this;

    }

    rtentry(rtentry &&other) noexcept {
        m_dst = other.m_dst;
        m_gateway = other.m_gateway;
        m_netmask = other.m_netmask;
        m_flags = other.m_flags;
        m_metric = other.m_metric;

        other.m_dst = 0;
        other.m_gateway = 0;
        other.m_netmask = 0;
        other.m_flags = 0;
        other.m_metric = 0;
    }

    rtentry &operator=(rtentry &&other) noexcept {
        if (this != &other) {
            m_dst = other.m_dst;
            m_gateway = other.m_gateway;
            m_netmask = other.m_netmask;
            m_flags = other.m_flags;
            m_metric = other.m_metric;

            other.m_dst = 0;
            other.m_gateway = 0;
            other.m_netmask = 0;
            other.m_flags = 0;
            other.m_metric = 0;

        }

        return *this;

    }


    uint32_t m_dst;
    uint32_t m_gateway;
    uint32_t m_netmask;
    uint8_t m_flags;
    uint32_t m_metric;
};

class ROUTE {
public:
    static ROUTE *instance();

    ROUTE(const ROUTE &) = delete;

    ROUTE &operator=(const ROUTE &) = delete;

    rtentry &lookup(uint32_t);

private:
    ROUTE();

    std::vector<rtentry> rt_list;

};

extern ROUTE *route;
#endif //VIRTND_ROUTE_H
