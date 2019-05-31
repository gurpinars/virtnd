#include <sys/epoll.h>
#include <cstring>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netdev.h>
#include <utils.h>
#include <tap.h>
#include <ethernet.h>
#include <arp.h>
#include <ip.h>
#include <pk_buff.h>

static constexpr int MAX_EVENTS = 32;


NetDev::NetDev(const char *addr, const char *hwaddr) :
        addr(inet_bf(addr)),
        MTU(1500) {

    printf("The device(%s) is up at %s\n", hwaddr, addr);

    std::sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &this->hwaddr[0],
                &this->hwaddr[1],
                &this->hwaddr[2],
                &this->hwaddr[3],
                &this->hwaddr[4],
                &this->hwaddr[5]);

    pkb = new pk_buff;

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1()");
        exit(EXIT_FAILURE);
    }

    struct epoll_event event{};
    memset(&event, 0, sizeof(event));
    event.data.fd = tapd->fd();
    event.events = EPOLLIN;

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


                pkb->data = new uint8_t[MTU];

                ssize_t nread = tapd->read(pkb->data, MTU);

                if (nread < 0) {
                    perror("Reading from interface");
                    exit(1);
                }

                pkb->len = nread;
                pkb->dev_addr=addr;
                memcpy(pkb->dev_hwaddr, hwaddr, 6);

                auto *eth = eth_hdr(pkb->data);
                eth->type = htons(eth->type);

                switch (eth->type) {
                    case ETH_P_ARP:
                        arp->recv(pkb);
                        break;
                    case ETH_P_IP:
                        ip->recv(pkb);
                        break;
                    default:
                        break;
                }

                delete[] pkb->data;
            }
        }

    }
}

NetDev::~NetDev() {
    close(epoll_fd);
    delete pkb->data;
    delete pkb;


}



