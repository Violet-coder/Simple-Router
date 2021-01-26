#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/*
The handle_arpreq() function is a function you should write, and it should handle sending ARP requests if necessary
*/
/*write handle_arpreq based on the pseudocode in the sr_arpcache.h*/
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* request){
    /* current time */
    time_t current_time = time(NULL);

    /*if the mutex is already locked, the calling thread blocks until the mutex becomes available.*/
    pthread_mutex_lock(&sr->cache.lock);

    if (difftime(current_time, request->sent)>1.0){
        if(request->times_sent >= 5){
            /*if ARP request has been sent more than 5 times, we should generate a ICMP host unreachable msg*/
            struct sr_packet* packet_walker = request->packets;
            while (packet_walker) {
                /*if 5 ARP requests were sent to the next-hop IP without a response
                send ICMP msg-destination host unreachable(type 3, code 1)*/
                send_icmp_msg_t3(sr, packet_walker->buf, packet_walker->len, 3, (uint8_t)1);
                packet_walker = packet_walker->next;
            }
            sr_arpreq_destroy(&sr->cache, request);
        } else {
            /* send frame to next hop and update time*/
            /*create new packet for ARP request*/
            unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t* arp_req_packet = malloc(len);

            /* find interface*/
            struct sr_if* interface = sr_get_interface(sr, request->packets->iface);
            if(!interface) {
                printf("Error(handle_arpreq): failed to get outgoing interface to send ARP request to next hop.\n");
                return;
            }

            /*build ARP request*/
            /*set ethernet header*/
            sr_ethernet_hdr_t* arp_req_eth_hdr = (sr_ethernet_hdr_t*)arp_req_packet;

            /*ARP requests should be sent to the broadcast MAC address(ff-ff-ff-ff-ff-ff)*/
            /*set the ethernet header*/
            memset(arp_req_eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
            memcpy(arp_req_eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
            arp_req_eth_hdr->ether_type = htons(ethertype_arp);

            /*set the ARP header*/
            sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(arp_req_packet+ sizeof(sr_ethernet_hdr_t));
            arp_hdr->ar_hrd = (unsigned short)htons(arp_hrd_ethernet);
            arp_hdr->ar_pro = (unsigned short)htons(ethertype_ip);
            arp_hdr->ar_hln = (unsigned char)ETHER_ADDR_LEN;
            arp_hdr->ar_pln = (unsigned char)sizeof(uint32_t);
            arp_hdr->ar_op = (unsigned short)htons(arp_op_request);
            memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = interface->ip;
            memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
            arp_hdr->ar_tip = request->ip;

            /*send ARP request packet*/
            sr_send_packet(sr, arp_req_packet, len, interface->name);
            free(arp_req_packet);

            /*update time */
            request->sent = time(NULL);
            request->times_sent = request->times_sent + 1;
        }
    }
    pthread_mutex_unlock(&sr->cache.lock);
}



/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
/*
get called every seconf to iterate through the ARP request queue and re-send ARP requests if necessary
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Fill this in */
    struct sr_arpreq* request = sr->cache.requests;
    while(request) {
        struct sr_arpreq* next_request = request->next;
        handle_arpreq(sr, request);
        request = next_request;
    }


}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}

