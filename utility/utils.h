#ifndef VIRTND_UTILS_H
#define VIRTND_UTILS_H

#include <iostream>

uint32_t inet_bf(const char *addr);
std::string inet_pf(uint32_t addr);
uint16_t checksum(void *, int);

#endif //VIRTND_UTILS_H
