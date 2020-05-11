#ifndef VIRTND_TAP_H
#define VIRTND_TAP_H

#include <string>
#include <unistd.h>
#include <iostream>


class TAPDev {
public:
    static TAPDev *instance();

    TAPDev(const TAPDev &) = delete;

    TAPDev &operator=(const TAPDev &) = delete;

    ssize_t read(void *buf, size_t len) const;

    ssize_t write(void *buf, size_t len) const;

    int fd() const { return tap_fd; }

private:
    explicit TAPDev(std::string &&dev);

    ~TAPDev() { close(tap_fd); }

    static int alloc(std::string &dev);

    int tap_fd;
    std::string addr;
    std::string route;

    static void set_iff_up(std::string &dev);

    void set_iff_address(std::string &dev);

    void set_iff_route(std::string &dev);
};

#define _TAPD() TAPDev::instance()
#endif //VIRTND_TAP_H
