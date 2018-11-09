#include <sys/epoll.h>
#include <cstring>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include "netdev.h"

static constexpr int MAX_EVENTS = 32;
static constexpr uint32_t MTU = 1500;

inline uint32_t inet_bf(const char *addr);

NetDev::NetDev(const char *addr, const char *hwaddr) :
        addr(inet_bf(addr)),
        tapd(std::make_shared<TAPDev>("tap0")),
        arp(std::make_shared<ARP>(tapd)) {

    std::sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &this->hwaddr[0],
                &this->hwaddr[1],
                &this->hwaddr[2],
                &this->hwaddr[3],
                &this->hwaddr[4],
                &this->hwaddr[5]);

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1()");
        exit(EXIT_FAILURE);
    }

    struct epoll_event event{};
    memset(&event, 0, sizeof(event));
    event.data.fd = tapd->fd();
    event.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tapd->fd(), &event) < 0) {
        perror("epoll_ctl()");
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }
}

void NetDev::loop() {
    std::array<struct epoll_event, ::MAX_EVENTS> events{};

    while (true) {
        int nevents = epoll_wait(epoll_fd, events.data(), ::MAX_EVENTS, -1);
        if (nevents < 0)
            perror("epoll_wait()");

        for (int i = 0; i < nevents; ++i) {
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP ||
                !(events[i].events & EPOLLIN)) {

                std::cerr << "epoll event error\n";
                close(events[i].data.fd);
            } else if (events[i].data.fd == tapd->fd()) {

                char buffer[MTU];
                ssize_t nread = tapd->read(buffer, sizeof(buffer));

                if (nread < 0) {
                    perror("Reading from interface");
                    exit(1);
                }

                auto *eth = eth_hdr(buffer);
                eth->type = htons(eth->type);

                switch (eth->type) {
                    case ETH_P_ARP:
                        arp->recv(eth, addr, hwaddr);
                        continue;
                    default:
                        continue;
                }
            }
        }

    }
}


inline uint32_t inet_bf(const char *addr) {
    uint32_t dst = 0;

    if (inet_pton(AF_INET, addr, &dst) != 1) {
        perror("inet binary formatting failed");
        exit(1);
    }

    return ntohl(dst);
}




