
#include <cstring>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/if_tun.h>
#include "tap.h"

TAPDev::TAPDev(std::string &&dev):
        addr("10.0.0.5"),
        route("10.0.0.0/24") {

    if ((tap_fd = alloc(dev)) < 0) {
        std::cerr << "Allocating interface\n";
        exit(1);
    }

    set_iff_up(dev);
    set_iff_address(dev);
    set_iff_route(dev);
}

int TAPDev::alloc(std::string &dev) {
    struct ifreq ifr{};
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Cannot open TUN/TAP dev");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (!dev.empty()) {
        strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ERR: Could not ioctl tun");
        close(fd);
        return err;
    }

    dev.erase();
    dev.append(ifr.ifr_name);
    return fd;
}

ssize_t TAPDev::read(void *buf, size_t len) {
    return ::read(tap_fd, buf, len);
}

ssize_t TAPDev::write(void *buf, size_t len) {
    return ::write(tap_fd, buf, len);
}


void TAPDev::set_iff_up(std::string &dev) {
    std::stringstream  ss;
    ss << "ip link set dev " << dev << " up";
    system(ss.str().c_str());
}

void TAPDev::set_iff_address(std::string &dev) {
    std::stringstream  ss;
    ss << "ip address add dev " << dev << " local " << addr;
    system(ss.str().c_str());
}

void TAPDev::set_iff_route(std::string &dev) {
    std::stringstream  ss;
    ss << "ip route add dev " <<  dev << " " << route;
    system(ss.str().c_str());
}



