#ifndef VIRTND_TAP_H
#define VIRTND_TAP_H

#include <string>
#include <unistd.h>
#include <iostream>


class TAPDev {
public:
    static TAPDev *instance();
    TAPDev(const TAPDev &) = delete;
    TAPDev &operator=(const TAPDev &)= delete;
    ssize_t read(void *, size_t);
    ssize_t write(void *, size_t);
    int fd() const { return tap_fd; }

private:
    explicit TAPDev(std::string &&);
    ~TAPDev() { close(tap_fd); }
    int alloc(std::string &);

    int tap_fd;
    std::string addr;
    std::string route;

    void set_iff_up(std::string &);
    void set_iff_address(std::string &);
    void set_iff_route(std::string &);
};

#define _TAPD() TAPDev::instance()
#endif //VIRTND_TAP_H
