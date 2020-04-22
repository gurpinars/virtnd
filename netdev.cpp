#include <sys/epoll.h>
#include <cstring>
#include <array>
#include "netdev.h"
#include "utility/utils.h"
#include "stack/tap.h"
#include "stack/pk_buff.h"

static constexpr int MAX_EVENTS = 32;


NetDev::NetDev(const char *addr, const char *hwaddr) :
        addr(inet_bf(addr)) {

    printf("The device(%s) is up at %s\n", hwaddr, addr);

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
    event.data.fd = _TAPD()->fd();
    event.events = EPOLLIN;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, _TAPD()->fd(), &event) < 0) {
        perror("epoll_ctl()");
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }
}

void NetDev::loop() {
    std::array<struct epoll_event, ::MAX_EVENTS> events{};

    while (true) {

        int nevents = epoll_wait(epoll_fd, events.data(), ::MAX_EVENTS, -1);
        if (nevents < 0) {
            if (errno == EINTR) {
                continue;
            }
        }
        for (int i = 0; i < nevents; ++i) {
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP ||
                !(events[i].events & EPOLLIN)) {

                std::cerr << "epoll event error\n";
                close(events[i].data.fd);
            } else if (events[i].data.fd == _TAPD()->fd()) {
                pk_buff pkb{};
                ssize_t nread = _TAPD()->read(pkb.data, MTU);

                if (nread < 0) {
                    perror("Reading from interface");
                    exit(1);
                }

                pkb.len = nread;
                pkb.dev_addr = addr;
                memcpy(pkb.dev_hwaddr, hwaddr, 6);

                this->notify(std::move(pkb));
            }
        }

    }
}

NetDev::~NetDev() {
    close(epoll_fd);
}



