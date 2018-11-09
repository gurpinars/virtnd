#include <iostream>
#include "netdev.h"


int main() {
    NetDev netd("10.0.0.1", "0e:7e:38:30:50:b0");
    netd.loop();

}
