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
