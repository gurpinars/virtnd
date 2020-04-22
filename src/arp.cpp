#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethernet.h"
#include "arp.h"
#include "pk_buff.h"

/*
 * rfc 826
 * https://tools.ietf.org/html/rfc826
 */

static constexpr uint16_t ARP_ETHERNET = 0x0001;
static constexpr uint16_t ARP_REQUEST = 0x0001;
static constexpr uint16_t ARP_IPV4 = 0x0800;
static constexpr uint16_t ARP_REPLY = 0x0002;

static constexpr uint8_t hwbroadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


ARP *ARP::instance() {
    static ARP ins;
    return &ins;
}

ARP::ARP() {
    ct.stop = false;
    ct.timeout = 5;
    ct.tid = std::thread(&ARP::check_trans_table, this);
}

ARP::~ARP() {
    std::lock_guard<std::mutex> lockg(ct.mutex);
    ct.stop = true;
    ct.tid.join();
}

void ARP::recv(pk_buff &&pkb) {
    auto eth = eth_hdr(pkb.data);
    auto arph = arp_hdr(eth);

    if (pkb.len < sizeof(eth_frame) + sizeof(arphdr)) {
        std::cerr << "ARP packet is too small\n";
        return;
    }


    arph->hrd = ntohs(arph->hrd);
    arph->pro = ntohs(arph->pro);
    arph->op = ntohs(arph->op);
    arph->tpa = ntohl(arph->tpa);
    arph->spa = ntohl(arph->spa);


    if (arph->hrd != ARP_ETHERNET && arph->hln != 0x06) {
        return;
    }

    if (arph->pro != ARP_IPV4 && arph->pln != 0x04) {
        return;
    }

    int merge = false;
    auto found = cache_lookup(arph->spa);
    if (found) {
        cache_update(arph->spa, arph->sha);
        merge = true;
    }

    if (pkb.dev_addr == arph->tpa) {
        if (!merge)
            cache_ent_create(arph->spa, arph->pro, arph->sha);
    } else
        return;

    switch (arph->op) {
        case ARP_REQUEST:
            std::cout << "Got 1 ARP Request\n";
            reply(std::move(pkb));
            break;
        default:
            break;
    }

}

void ARP::reply(pk_buff &&pkb) {
    auto eth = eth_hdr(pkb.data);
    auto arph = arp_hdr(eth);

    memcpy(arph->tha, arph->sha, 6);
    arph->tpa = arph->spa;

    eth->type = htons(eth->type);

    memcpy(arph->sha, pkb.dev_hwaddr, 6);
    arph->spa = htonl(pkb.dev_addr);

    arph->op = ARP_REPLY;
    arph->op = htons(arph->op);

    arph->hrd = htons(arph->hrd);
    arph->pro = htons(arph->pro);

    _ETH()->xmit(std::move(pkb), arph->tha, arph->sha, pkb.len, ETH_P_ARP);


}

void ARP::request(pk_buff &&pkb, uint32_t addr, uint32_t tpa) {
    auto eth = eth_hdr(pkb.data);
    auto arph = arp_hdr(eth);

    memcpy(arph->sha, pkb.dev_hwaddr, 6);
    arph->spa = addr;

    memcpy(arph->tha, hwbroadcast, 6);
    arph->tpa = tpa;

    arph->op = htons(ARP_REQUEST);
    arph->hrd = htons(ARP_ETHERNET);
    arph->pro = htons(ARP_IPV4);
    arph->hln = 0x06;
    arph->pln = 0x04;

    arph->spa = htonl(arph->spa);
    arph->tpa = htonl(arph->tpa);


    size_t len = sizeof(struct arphdr) + sizeof(struct eth_frame);

    _ETH()->xmit(std::move(pkb), arph->tha, arph->sha, len, ETH_P_ARP);

}

void ARP::check_trans_table(void *contex) {
    auto ctx = static_cast<ARP *>(contex);
    while (!ctx->ct.stop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        time_t now;
        now = time(nullptr);

        for (auto it = ctx->trans_table.cbegin(); it != ctx->trans_table.cend();) {
            if (difftime(now, it->second.time) > ctx->ct.timeout) {
                ctx->trans_table.erase(it++);
            } else ++it;
        }

    }
}


arp_cache ARP::cache_lookup(uint32_t addr) {
    auto found = trans_table.find(addr);
    if(found)
        return found;
    return {};
}

void ARP::cache_update(uint32_t addr, uint8_t *sha) {
    arp_cache cache{};
    memcpy(cache.hwaddr, sha, 6);
    cache.time = time(nullptr);
    trans_table.update(addr, std::move(cache));
}

void ARP::cache_ent_create(uint32_t addr, uint16_t pro, uint8_t *sha) {
    arp_cache cache{};
    cache.pro = pro;
    cache.time = time(nullptr);
    memcpy(cache.hwaddr, sha, 6);
    trans_table.insert(addr, std::move(cache));
}

