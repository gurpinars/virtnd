#ifndef VIRTND_ARP_H
#define VIRTND_ARP_H

#include <cstdint>
#include <map>
#include <thread>
#include <mutex>
#include <ethernet.h>
#include <pk_buff.h>


struct arp_cache {
    uint8_t hwaddr[6];  /* Sender Hardware Address */
    uint16_t pro;       /* Protocol type */
    time_t time;
    bool filled;
};


class ARP {
public:
    static ARP *instance();
    ARP(const ARP &) = delete;
    ARP &operator=(const ARP &)= delete;
    void recv(pk_buff *);
    void request(pk_buff *, uint32_t, uint32_t);
    arp_cache cache_lookup(uint32_t);

private:
    explicit ARP();
    ~ARP();
    void reply(pk_buff *);
    void cache_update(uint32_t, uint8_t *);
    void cache_ent_create(uint32_t, uint16_t, uint8_t *);

    struct arphdr {
        uint16_t hrd;           /* Hardware type */
        uint16_t pro;           /* Protocol type */
        uint8_t hln;            /* Hardware Address Length */
        uint8_t pln;            /* Protocol Address Length */
        uint16_t op;            /* Opcode */
        uint8_t sha[6];         /* Sender Hardware Address */
        uint32_t spa;           /* Sender Protocol Address */
        uint8_t tha[6];         /* Target Hardware Address */
        uint32_t tpa;           /* Target Protocol Address */
    } __attribute__((packed));

    typedef struct {
        std::thread tid;   /* Thread */
        std::mutex mutex;  /* Data mutex */
        int timeout;
        bool stop;
    } cache_timer;

    cache_timer ct{};
    std::map<uint32_t, arp_cache> trans_table;  /*Translation table*/

    inline struct arphdr *arp_hdr(eth_frame *eth) {
        return reinterpret_cast<arphdr *>(eth->payload);
    }

    static void chck_table(void *contex);

};

extern ARP *arp;
#endif //VIRTND_ARP_H
