#ifndef TCP_IP_TAP_H
#define TCP_IP_TAP_H

#include <string>
#include <unistd.h>
#include <iostream>


class TAPDev {
public:
    explicit TAPDev(std::string &&);
    ~TAPDev() { close(tap_fd);}

    ssize_t read(void *, size_t);
    ssize_t write(void *, size_t);

    int fd() const { return tap_fd; }

private:
    int alloc(std::string &);
    int tap_fd;
    std::string addr;
    std::string route;
    void set_iff_up(std::string &);
    void set_iff_address(std::string &);
    void set_iff_route(std::string &);
};

#endif //TCP_IP_TAP_H
