#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "arp.h"
#include "tap.h"

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
    ct.timeout = 600;

    if (pthread_mutex_init(&ct.mutex, nullptr) != 0) {
        throw std::runtime_error("Mutex initialization failed");
    }

    if (pthread_create(&ct.tid, nullptr, &chck_table, this) != 0) {
        pthread_mutex_destroy(&ct.mutex);
        throw std::runtime_error("Failed to start a thread for arp cache");
    }

}

ARP::~ARP() {
    ct.stop = true;
    pthread_join(ct.tid, nullptr);
    pthread_mutex_destroy(&ct.mutex);
}

void ARP::recv(pk_buff *pkb, uint32_t addr, uint8_t hwaddr[]) {
    struct eth_frame *eth;
    eth = eth_hdr(pkb->data);

    struct arp_hdr *arph;
    arph = emit_hdr(eth);

    if (pkb->len < sizeof(eth_frame) + sizeof(arp_hdr)) {
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
    arp_cache found = cache_lookup(arph->spa);
    if (found.time) {
        cache_update(arph->spa, arph->sha);
        merge = true;
    }

    if (addr == arph->tpa && !merge) {
        cache_ent_create(arph->spa, arph->pro, arph->sha);
    } else
        return;

    switch (arph->op) {
        case ARP_REQUEST:
            std::cout << "Got 1 ARP Request\n";
            reply(pkb, addr, hwaddr);
            break;
        default:
            break;
    }

}

void ARP::reply(pk_buff *pkb, uint32_t addr, uint8_t hwaddr[]) {
    struct arp_hdr *arph;
    struct eth_frame *eth;

    eth = eth_hdr(pkb->data);

    arph = emit_hdr(eth);

    memcpy(arph->tha, arph->sha, 6);
    arph->tpa = arph->spa;

    eth->type = htons(eth->type);

    memcpy(arph->sha, hwaddr, 6);
    arph->spa = htonl(addr);

    memcpy(eth->dmac, arph->tha, 6);
    memcpy(eth->smac, arph->sha, 6);

    arph->op = ARP_REPLY;
    arph->op = htons(arph->op);

    arph->hrd = htons(arph->hrd);
    arph->pro = htons(arph->pro);

    tapd->write(pkb->data, pkb->len);

}

void ARP::request(pk_buff *pkb, uint32_t addr, uint8_t hwaddr[], uint32_t tpa) {
    struct arp_hdr *arp;
    struct eth_frame *eth;

    eth = eth_hdr(pkb->data);
    arp = emit_hdr(eth);

    memcpy(arp->sha, hwaddr, 6);
    arp->spa = addr;

    memcpy(arp->tha, hwbroadcast, 6);
    arp->tpa = tpa;

    arp->op = htons(ARP_REQUEST);
    arp->hrd = htons(ARP_ETHERNET);
    arp->pro = htons(ARP_IPV4);
    arp->hln = 0x06;
    arp->pln = 0x04;

    arp->spa = htonl(arp->spa);
    arp->tpa = htonl(arp->tpa);

    memcpy(eth->dmac, hwbroadcast, 6);
    memcpy(eth->smac, hwaddr, 6);
    eth->type = htons(ETH_P_ARP);

    size_t len = sizeof(struct arp_hdr) + sizeof(struct eth_frame);
    tapd->write(pkb->data, len);
}

void *ARP::chck_table(void *contex) {
    auto ctx = static_cast<ARP *>(contex);
    while (!ctx->ct.stop) {
        sleep(1);

        time_t now;
        now = time(nullptr);

        pthread_mutex_lock(&ctx->ct.mutex);
        for (auto &el:ctx->trans_table) {
            if (difftime(now, el.second.time) > ctx->ct.timeout) {
                ctx->trans_table.erase(el.first);
                // debug
//                if (!ctx->trans_table.empty())
//
//                    printf("%s Cache cleaned:Key: %s \tMac:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n\n",ctime(&now),inet_pf(el.first).c_str(),
//                       ctx->trans_table[el.first].hwaddr[0],ctx->trans_table[el.first].hwaddr[1],
//                       ctx->trans_table[el.first].hwaddr[2],ctx->trans_table[el.first].hwaddr[3],
//                       ctx->trans_table[el.first].hwaddr[4],ctx->trans_table[el.first].hwaddr[5]);
            }
        }
        pthread_mutex_unlock(&ctx->ct.mutex);

    }
}


arp_cache ARP::cache_lookup(uint32_t addr) {
    arp_cache c{};
    memset(&c, 0, sizeof(c));
    pthread_mutex_lock(&ct.mutex);
    auto f = trans_table.find(addr);
    if (f != trans_table.end()) {
//        printf("********* Cache found %s %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n\n",inet_pf(addr).c_str(),
//               f->second.hwaddr[0],f->second.hwaddr[1],f->second.hwaddr[2],f->second.hwaddr[3],
//               f->second.hwaddr[4],f->second.hwaddr[5]);
        c = f->second;
    }
    pthread_mutex_unlock(&ct.mutex);
    return c;

}

void ARP::cache_update(uint32_t addr, uint8_t *sha) {
    pthread_mutex_lock(&ct.mutex);
    memcpy(trans_table[addr].hwaddr, sha, 6);
    trans_table[addr].time = time(nullptr);

//    printf("%s Cache updated:Key: %s \tMac:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n\n",ctime(&now),inet_pf(addr).c_str(),
//           trans_table[addr].hwaddr[0],trans_table[addr].hwaddr[1],trans_table[addr].hwaddr[2],trans_table[addr].hwaddr[3],
//           trans_table[addr].hwaddr[4],trans_table[addr].hwaddr[5]);

    pthread_mutex_unlock(&ct.mutex);

}

void ARP::cache_ent_create(uint32_t addr, uint16_t pro, uint8_t *sha) {
    pthread_mutex_lock(&ct.mutex);
    arp_cache c{};
    c.pro = pro;
    c.time = time(nullptr);
    memcpy(c.hwaddr, sha, 6);
    trans_table.insert(std::make_pair(addr, c));

//    printf("%s Cache ent created:%d \t%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n\n",ctime(&c.time),addr,
//           trans_table[addr].hwaddr[0],trans_table[addr].hwaddr[1],trans_table[addr].hwaddr[2],trans_table[addr].hwaddr[3],
//           trans_table[addr].hwaddr[4],trans_table[addr].hwaddr[5]);

    pthread_mutex_unlock(&ct.mutex);

}

ARP *arp = ARP::instance();










