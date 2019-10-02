#include <cstdint>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include "utils.h"

uint32_t inet_bf(const char *addr) {
    struct in_addr ia{};

    if (inet_pton(AF_INET, addr, &ia) != 1) {
        perror("inet binary formatting failed");
        exit(1);
    }

    return ntohl(ia.s_addr);
}

std::string inet_pf(uint32_t addr) {
    struct in_addr ia{};
    ia.s_addr = addr;
    return inet_ntoa(ia);
}

uint16_t checksum(void *addr, int count) {

    /* Compute Internet Checksum for "count" bytes
     *    beginning at location "addr".
     *    https://tools.ietf.org/html/rfc1071
     */

    register uint32_t sum = 0;

    auto *ptr_16 = static_cast<uint16_t *>(addr);

    for (; count > 1; count -= 2) {
        // This is the inner loop
        sum += *ptr_16++;
    }

    // Add left-over byte, if any
    if (count > 0)
        sum += *static_cast<uint8_t *>(addr);

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
