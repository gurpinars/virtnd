#include <netinet/in.h>
#include "packet_processor.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"


PacketProcessor::PacketProcessor() :
        stop(false),
        m_thread([this]() { this->worker(); }) {}

PacketProcessor::~PacketProcessor() {
    stop = true;
    m_thread.join();
}

void PacketProcessor::update(pk_buff pkt) {
    std::lock_guard<std::mutex> lockg(mutex);
    pkt_queue.push(std::move(pkt));

}

void PacketProcessor::worker() {
    while (!stop || !pkt_queue.empty()) {
        if (pkt_queue.empty())
            continue;

        mutex.lock();
        auto &&pkb = pkt_queue.front();
        pkt_queue.pop();
        mutex.unlock();

        auto *eth = eth_hdr(pkb.data);
        eth->type = htons(eth->type);

        switch (eth->type) {
            case ETH_P_ARP:
                arp->recv(std::move(pkb));
                break;
            case ETH_P_IP:
                ip->recv(std::move(pkb));
                break;
            default:
                break;
        }
    }
}