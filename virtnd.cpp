#include <iostream>
#include <memory>
#include "netdev.h"
#include "packet_processor.h"


int main() {
    std::unique_ptr<NetDev> netd;
    std::unique_ptr<PacketProcessor> pprocessor;

    netd = std::make_unique<NetDev>("10.0.0.1", "0e:7e:38:30:50:b0");
    pprocessor = std::make_unique<PacketProcessor>();
    
    netd->attach(pprocessor.get());
    netd->loop();
}
