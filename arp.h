#ifndef TCP_IP_ARP_H
#define TCP_IP_ARP_H

#include <cstdint>
#include <map>
#include <vector>
#include <pthread.h>
#include <memory>
#include "ethernet.h"
#include "tap.h"


class ARP {
public:
    explicit ARP(std::shared_ptr<TAPDev> &tapd);
    ~ARP();
    void recv(struct eth_frame *, uint32_t, uint8_t[]);
    void request(struct eth_frame *, uint32_t, uint8_t[],uint32_t);


private:
    struct arp_hdr {
        uint16_t hrd;       /* Hardware type */
        uint16_t pro;       /* Protocol type */
        uint8_t hln;        /* Hardware Address Length */
        uint8_t pln;        /* Protocol Address Length */
        uint16_t op;        /* Opcode */
        uint8_t sha[6];     /* Sender Hardware Address */
        uint32_t spa;       /* Sender Protocol Address */
        uint8_t tha[6];     /* Target Hardware Address */
        uint32_t tpa;       /* Target Protocol Address */
    } __attribute__((packed));

    struct arp_cache {
        uint8_t sha[6];     /* Sender Hardware Address */
        uint16_t pro;       /* Protocol type */
        time_t time;
    };

    typedef struct {
        pthread_t thread;       /* Thread */
        pthread_mutex_t mutex;  /* Data mutex */
        int timeout;
        bool stop;
    } cache_timer;

    std::shared_ptr<TAPDev> &tapd;              /*Linux TAP device*/
    cache_timer ct{};                           /*ARP cache thread structure*/
    std::map<uint32_t, arp_cache> trans_table;  /*Translation table*/

    inline struct arp_hdr *emit_hdr(eth_frame *eth) {
        return reinterpret_cast<arp_hdr *>(eth->payload);
    }

   static void *chck_table(void *contex);       /* Cache timer thread start point */

};


#endif //TCP_IP_ARP_H
