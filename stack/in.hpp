#pragma once

#include <cstdint>

namespace stack {
namespace in {

namespace {

#define __swap_16(n) ( ((((uint16_t)(n) & 0xffu) << 8u) | (((uint16_t)(n) & 0xff00u) >> 8u)) )

#define __swap_32(n) ( ((((uint32_t)(n) & 0xffu)) << 24u) |   \
                  ((((uint32_t)(n) & 0xff00u)) << 8u)     |   \
                  ((((uint32_t)(n) & 0xff0000u)) >> 8u)   |   \
                  ((((uint32_t)(n) & 0xff000000u)) >> 24u))

template<typename T>
inline T MAKE_FUNC(T x, T swap_macro) {
#if BYTE_ORDER == BIG_ENDIAN
    return x;
#elif BYTE_ORDER == LITTLE_ENDIAN
    return swap_macro;
#else
# error "What kind of system is this?"
#endif
}

}

inline uint16_t ntohs(uint16_t x) {
    return MAKE_FUNC<uint16_t>(x, __swap_16(x));
}

inline uint16_t htons(uint16_t x) {
    return MAKE_FUNC<uint16_t>(x, __swap_16(x));
}

inline uint32_t ntohl(uint32_t x) {
    return MAKE_FUNC<uint32_t>(x, __swap_32(x));
}

inline uint32_t htonl(uint32_t x) {
    return MAKE_FUNC<uint32_t>(x, __swap_32(x));
}

}
}