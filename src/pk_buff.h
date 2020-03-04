#ifndef VIRTND_PK_BUFF_H
#define VIRTND_PK_BUFF_H

#include <cstring>
#include "route.h"

static constexpr uint32_t MTU = 1500;

typedef struct pk_buff_t {
    pk_buff_t() = default;
    pk_buff_t(const pk_buff_t &other) {
        len = other.len;
        dev_addr = other.dev_addr;
        memcpy(data, other.data, MTU);
        memcpy(dev_hwaddr, other.dev_hwaddr, 6);
        rtdst = other.rtdst;
    }

    pk_buff_t(pk_buff_t &&other) noexcept {
        len = other.len;
        dev_addr = other.dev_addr;
        memcpy(data, other.data, MTU);
        memcpy(dev_hwaddr, other.dev_hwaddr, 6);
        rtdst = std::move(other.rtdst);

        other.len = 0;
        other.dev_addr = 0;
        memset(other.data, 0, MTU);
        memset(other.dev_hwaddr, 0, 6);
    }

    pk_buff_t &operator=(pk_buff_t &&other) noexcept {
        if (this != &other) {
            len = other.len;
            dev_addr = other.dev_addr;
            memcpy(data, other.data, MTU);
            memcpy(dev_hwaddr, other.dev_hwaddr, 6);
            rtdst = std::move(other.rtdst);

            other.len = 0;
            other.dev_addr = 0;
            memset(other.data, 0, MTU);
            memset(other.dev_hwaddr, 0, 6);

        }

        return *this;

    }


    ssize_t len{};
    uint8_t data[MTU]{};
    uint8_t dev_hwaddr[6]{};
    uint32_t dev_addr{};
    rtentry rtdst{};

} pk_buff;

#endif //VIRTND_PK_BUFF_H
