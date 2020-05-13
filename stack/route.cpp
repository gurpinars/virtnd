#include "../utility/utils.h"
#include "route.h"


ROUTE *ROUTE::instance() {
    static ROUTE ins;
    return &ins;
}

ROUTE::ROUTE() {
    rt_list.emplace_back(inet_bf("10.0.0.1"), 0, 0xffffff00, RT_HOST, 0);
    rt_list.emplace_back(inet_bf("127.0.0.1"), 0, 0xff000000, RT_LOOPBACK, 0);
    rt_list.emplace_back(0, inet_bf("10.0.0.5"), 0, RT_GATEWAY, 0);
}

rtentry ROUTE::lookup(uint32_t daddr) {
    for (auto &r:rt_list) {
        if ((daddr & r.m_netmask) == (r.m_dst & r.m_netmask))
            return r;
    }
    return {};
}

