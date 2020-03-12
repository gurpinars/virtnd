#ifndef VIRTND_PACKETPROCESSOR_H
#define VIRTND_PACKETPROCESSOR_H

#include <thread>
#include <mutex>
#include <queue>
#include "observer.hpp"
#include "concurrent_queue.hpp"
#include "pk_buff.h"

class PacketProcessor: public Observer<pk_buff&&> {
public:
    PacketProcessor();
    ~PacketProcessor();
    void update(pk_buff data) override;
    
private:
    void worker();
    std::thread m_thread;   /* Thread */
    std::mutex mutex;       /* Data mutex */
    bool stop;
    concurrent_queue<pk_buff> pkt_queue;

};

#endif
