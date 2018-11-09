#include <netinet/in.h>
#include <iostream>
#include <cstring>
#include <linux/if_ether.h>
#include "arp.h"

static const uint16_t ARP_ETHERNET = 0x0001;
static const uint16_t ARP_REQUEST = 0x0001;
static const uint16_t ARP_IPV4 = 0x0800;
static const uint16_t ARP_REPLY = 0x0002;

static const uint8_t hwbroadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

ARP::ARP(std::shared_ptr<TAPDev> &tapd) :
        tapd(tapd) {
    ct.stop = false;
    ct.timeout = 10;

    if (pthread_mutex_init(&ct.mutex, nullptr) != 0) {
        throw std::runtime_error("Mutex initialization failed");
    }

    if (pthread_create(&ct.thread, nullptr, &chck_table, this) != 0) {
        pthread_mutex_destroy(&ct.mutex);
        throw std::runtime_error("Failed to start a thread for arp cache");
    }

}

ARP::~ARP() {
    ct.stop = true;
    pthread_join(ct.thread, nullptr);
    pthread_mutex_destroy(&ct.mutex);
}

void ARP::recv(struct eth_frame *eth, uint32_t addr, uint8_t hwaddr[]) {
    struct arp_hdr *arp;

    arp = emit_hdr(eth);

    arp->hrd = ntohs(arp->hrd);
    arp->pro = ntohs(arp->pro);
    arp->op = ntohs(arp->op);
    arp->tpa = ntohl(arp->tpa);


    if (arp->hrd != ARP_ETHERNET && arp->hln != 0x06) {
        return;
    }

    if (arp->pro != ARP_IPV4 && arp->pln != 0x04) {
        return;
    }

    int merge = false;
    pthread_mutex_lock(&ct.mutex);
    auto it = trans_table.find(arp->spa);
    if (it != trans_table.end()) {
        memcpy(it->second.sha, arp->sha, 6);
        merge = true;
    }
    pthread_mutex_unlock(&ct.mutex);

    if (addr == arp->tpa) {
        if (!merge) {
            pthread_mutex_lock(&ct.mutex);
            arp_cache c{};
            c.pro = arp->pro;
            c.time = time(nullptr);
            memcpy(c.sha, arp->sha, 6);
            auto spa = arp->spa;
            trans_table.insert(std::pair<uint32_t, arp_cache>(spa, c));
            pthread_mutex_unlock(&ct.mutex);
        }
    } else
        return;

    switch (arp->op) {
        case ARP_REQUEST: {
            memcpy(arp->tha, arp->sha, 6);
            arp->tpa = arp->spa;

            eth->type = htons(eth->type);

            memcpy(arp->sha, hwaddr, 6);
            arp->spa = htonl(addr);

            memcpy(eth->dmac, arp->tha, 6);
            memcpy(eth->smac, arp->sha, 6);

            arp->op = ARP_REPLY;
            arp->op = htons(arp->op);

            arp->hrd = htons(arp->hrd);
            arp->pro = htons(arp->pro);

            size_t len = sizeof(struct arp_hdr) + sizeof(struct eth_frame);
            tapd->write((void *) eth, len);
            return;
        }
        default:
            return;
    }

}

void ARP::request(struct eth_frame *eth, uint32_t addr, uint8_t hwaddr[], uint32_t tpa) {
    struct arp_hdr *arp;

    arp = emit_hdr(eth);

    memcpy(arp->sha, hwaddr, 6);
    arp->spa = addr;

    memcpy(arp->tha, hwbroadcast, 6);
    arp->tpa = tpa;

    arp->op = htons(ARP_REQUEST);
    arp->hrd = htons(ARP_ETHERNET);
    arp->pro = htons(ARP_IPV4);
    arp->hln = 0x06;
    arp->pln=  0x04;

    arp->spa = htonl(arp->spa);
    arp->tpa = htonl(arp->tpa);

    memcpy(eth->dmac, hwbroadcast, 6);
    memcpy(eth->smac, hwaddr, 6);
    eth->type = htons(ETH_P_ARP);

    size_t len = sizeof(struct arp_hdr) + sizeof(struct eth_frame);
    tapd->write((void *) eth, len);
}

void *ARP::chck_table(void *contex) {
    auto ctx = static_cast<ARP *>(contex);
    while (!ctx->ct.stop) {
        sleep(1);

        time_t now;
        now = time(nullptr);

        pthread_mutex_lock(&ctx->ct.mutex);
        for (auto const &el:ctx->trans_table) {
            if (difftime(now, el.second.time) > ctx->ct.timeout) {
                ctx->trans_table.erase(el.first);
            }
        }
        pthread_mutex_unlock(&ctx->ct.mutex);

    }
}







