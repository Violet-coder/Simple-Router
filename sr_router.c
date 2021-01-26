/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"



/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/


/*sr_handlepacket is called by the router each time a packet is received*/
/*sr_handlepacket is used for the router to deal with raw ethernet frame*/
void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);


    /* fill in code here */
    /*get to know the type of the packet: IP packet or ARP packet*/
    uint16_t packet_type = ethertype(packet);

    /*Two cases: receive an IP packet or an ARP packet*/
    switch(packet_type) {
        case ethertype_ip: {
            handle_ip_pkt(sr, packet, len, interface);
            break;
        }

        case ethertype_arp: {
            handle_arp_pkt(sr, packet, len, interface);
            break;
        }


    }



}/* end sr_ForwardPacket */

/*handle ip packet is used to handle the workflow of the router when it receive an IP packet*/
void handle_ip_pkt(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
    printf("Received IP packet\n");
    /*sanity-check the packet(meets minimum length and has correct checksum)*/
    /*check length:meets minimum length*/
    if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)))
    {
        printf("Error(handle_ip_pkt): Ethernet packet receieved is too short.\n");
        return;
    }

    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /*checksum:has correct checksum*/
    uint16_t temporary_ip_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if(temporary_ip_sum != cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
    {
        ip_hdr->ip_sum = temporary_ip_sum;
        printf(" IP packet checksum is not correct.\n");
        return;
    }
    else
        ip_hdr->ip_sum = temporary_ip_sum;

    /*check to see whether the IP packet is for this router*/
    struct sr_if* out_interface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    /*use sr_get_interface_by_ip to find whether the packet is for this router*/
    /*this packet is for me*/
    if(out_interface) {
        printf("Packet is for this router.\n");

        /*if this IP packet is for this router, check the type of the IP protocol in the ip header to get
        the type of the packet*/
        switch(ip_hdr->ip_p) {
            /*if it is a ICMP packet*/
            case ip_protocol_icmp: {
                /* check the header of the msg to see if it is an ICMP echo request*/
                sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
                /*If it is ICMP echo request, need to generate ICMP msg-echo reply(type 0)*/
                if(icmp_hdr->icmp_type == 0x08) {
                    send_icmp_msg_t0(sr, packet,len, 0, (uint8_t)0);
                }
                break;
            }

            /*If this IP packet contains an UDP or TCP payload sent to one of the router's interface
             * need to generate ICMP msg-port unreachable(type3, code3)*/
            case ip_protocol_tcp:
            case ip_protocol_udp:{
                printf("Packet containing a UDP/TCP payload is sent to one of the router's interfaces.\n");
                /*send ICMP msg-port unreachable(type 3, code 3)*/
                send_icmp_msg_t3(sr, packet,len,3, (uint8_t)3);
                break;
            }
        }

    }else{
        printf("Packet is not for this router, it is destined to other place.\n");
        /*decrease the TTL by 1*/
        ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
        /*if ttl becomes to 0, it means this packet is timeout*/
        if(ip_hdr->ip_ttl == 0) {
            printf("Time out(TTL decreased to 0).\n");
            /*If this IP packet is timeout,need to generate ICMP msg-time exceed(type 11, code 0)*/
            send_icmp_msg_t3(sr, packet, len, 11, (uint8_t)0);
            return;
        }

        /*recompute the packet checksum over the modified header*/
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /*check routing table perform LPM*/
        struct sr_rt* longest_prefix_match_entry = longest_prefix_match(sr, ip_hdr->ip_dst);
        if(!longest_prefix_match_entry){
            /*No match, ICMP net unreachable*/
            printf("Error(handle_ip_pkt(longest_prefix_match_entry:not found)): destination IP does not exist in the routing table.\n");
            send_icmp_msg_t3(sr, packet, len, 3, (uint8_t)0);
            return;
        }

        /*match exists, try to find the interface to send the packet out*/
        struct sr_if* out_interface_to_use = sr_get_interface(sr, longest_prefix_match_entry->interface);
        if(!out_interface_to_use){
            printf("Error(handle_ip_pkt): no interface found to send the packet\n");
            return;
        }

        /*if all pass, forward the packet to its destination*/
        send_pkt(sr, packet, len, out_interface_to_use, longest_prefix_match_entry->gw.s_addr);

    }

}


/*handle arp packet is used to handle the workflow of the router when it receive an ARP packet*/
void handle_arp_pkt(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
    printf("Received ARP packet\n");
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *)packet;

    /*extract the ARP header from the packet*/
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* out_interface = sr_get_interface(sr, interface);

    /*check whether this packet is an ethernet frame*/
    if(ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        printf("Error(handle_arp_pkt): packet is not an Ethernet frame.\n");
        return;
    }

    /*extract the ARP operation code to check whether it is an ARP request or ARP reply*/
    uint16_t ARP_opcode = ntohs(arp_hdr->ar_op);
    switch(ARP_opcode) {
        /*if it is an ARP request to the router*/
        case arp_op_request:
            sr_handle_arp_request(sr, ethernet_hdr, arp_hdr, out_interface);
            break;
        /*if it is an ARP reply to the router  */
        case arp_op_reply:
            sr_handle_arp_reply(sr, arp_hdr, out_interface);
            break;
    }


}

/*sr_handle_arp_request is used to handle the workflow of the router when it receive an ARP request*/
void sr_handle_arp_request(struct sr_instance* sr, sr_ethernet_hdr_t* old_e_hdr,sr_arp_hdr_t* old_arp_hdr, struct sr_if* interface){
    printf("Received ARP packet--ARP request.\n");
    /*construct an ARP reply*/
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* arp_rep_packet = malloc(len);

    /* set Ethernet hdr */
    sr_ethernet_hdr_t* new_e_hdr = (sr_ethernet_hdr_t*)arp_rep_packet;
    /* set ARP hdr */
    sr_arp_hdr_t* new_arp_hdr = (sr_arp_hdr_t*)(arp_rep_packet+ sizeof(sr_ethernet_hdr_t));
    /* set destination MAC to be the source MAC */
    new_e_hdr->ether_type = old_e_hdr->ether_type;
    memcpy(new_e_hdr->ether_dhost, old_e_hdr->ether_shost, ETHER_ADDR_LEN);
    /* set source MAC to be the incoming interface's MAC */
    memcpy(new_e_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    /* set the property of the  ARP hdr */

    /* change to reply type */
    new_arp_hdr->ar_op = htons(arp_op_reply);
    new_arp_hdr->ar_sip = interface->ip;
    new_arp_hdr->ar_tip = old_arp_hdr->ar_sip;
    new_arp_hdr->ar_hrd = old_arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = old_arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = old_arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = old_arp_hdr->ar_pln;

    memcpy(new_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    memcpy(new_arp_hdr->ar_tha, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);

    /*debug test the IP addr is correct*/
    /*print_addr_ip_int(ntohl(new_arp_hdr->ar_tip));*/

    /*send the new packet-ARP reply back*/
    sr_send_packet(sr, arp_rep_packet, len, interface->name);
}

/*handle arp packet is used to handle the workflow of the router when it receive an ARP reply*/
void sr_handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* old_arp_hdr,struct sr_if* interface){
    printf("Received ARP packet--ARP reply.\n");
    /*print_hdr_arp(old_arp_hdr);
    print_addr_ip_int(ntohl(old_arp_hdr->ar_sip));*/

    /*receive the reply, cache it*/
    struct sr_arpreq* cached = sr_arpcache_insert(&sr->cache, old_arp_hdr->ar_sha,
                                                  old_arp_hdr->ar_sip);
    if(cached) {
        struct sr_packet* packet_walker = cached->packets;
        /* go through all the packets waiting for this reply*/
        while (packet_walker){
            /*send outstanding packets*/
            uint8_t* new_packet = packet_walker->buf;
            sr_ethernet_hdr_t* new_e_hdr = (sr_ethernet_hdr_t*)(new_packet);
            sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet+sizeof(sr_ethernet_hdr_t));

            memcpy(new_e_hdr->ether_dhost, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(new_e_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

            /*checksum*/
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            printf("Get the arp reply, send the following packet.\n");
            print_hdrs(new_packet,packet_walker->len);

            sr_send_packet(sr, new_packet, packet_walker->len, interface->name);

            packet_walker = packet_walker->next;
        }
        /*After sending the reply for the request, drop the request from the queue*/
        sr_arpreq_destroy(&sr->cache, cached);
    }


}




/*The functions send_icmp_msg_tx below are used to construct ICMP packet and send packet back to the sending host */
/*Based on the packet we have received before we add ICMP header to construct a ICMP packet*/
/*send_icmp_msg_t0: send type 0 ICMP msg-echo reply*/
void send_icmp_msg_t0(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code){
    printf("Send icmp message type 0-echo reply.\n");
    /*set ethernet header*/
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
    /*set ip header*/
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    /*printf("IP header in echo req:\n");
    print_addr_ip_int(ip_hdr->ip_src);*/

    /*perform LPM to find the longest prefix match entry*/
    struct sr_rt* longest_prefix_match_entry = longest_prefix_match(sr, ip_hdr->ip_src);

    if(!longest_prefix_match_entry){
        /*Not match,failed to send the msg*/
        printf("Error(send_icmp_msg_t0): destination IP does not exist in the routing table when trying to send icmp type 0 message.\n");
        return;
    }

    /*find the interface to send the packet*/
    struct sr_if* out_interface = sr_get_interface(sr, longest_prefix_match_entry->interface);

    /*ICMP echo reply will be sent back to the sending host*/
    /*set the ethernet header*/
    memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

    /*set the icmp header*/
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;

    /*set the ip header*/
    uint32_t temporary_addr = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = temporary_addr;

    /*set the checksum*/
    int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, len - icmp_offset);

    /*send ICMP packet*/
    send_pkt(sr, packet, len, out_interface, longest_prefix_match_entry->gw.s_addr);

}

/*send_icmp_msg_t3: send type 3 or type11 ICMP msg-echo reply(depending on the type and code passed in)*/
void send_icmp_msg_t3(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code)
{
    printf("Send icmp message type 3.\n");
    /*set ethernet header*/
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;

    /*set ip header*/
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /*perform LPM to find the longest prefix match entry*/
    struct sr_rt* longest_prefix_match_entry = longest_prefix_match(sr, ip_hdr->ip_src);

    if(!longest_prefix_match_entry){
        /*Not match,failed to send the msg*/
        printf("Error(send_icmp_msg_t3): destination IP does not exist in the routing table when trying to send icmp type3/type11 message.\n");
        return;
    }

    /*find the interface to send the packet*/
    struct sr_if* out_interface = sr_get_interface(sr, longest_prefix_match_entry->interface);

    /*create new icmp packet*/
    unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* new_icmp_packet = malloc(new_len);

    /* sanity check */
    /*assert(new_icmp_packet);*/

    /* set ethernet header */
    sr_ethernet_hdr_t* new_eth_hdr = (sr_ethernet_hdr_t*)new_icmp_packet;

    /* create IP header */
    sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_icmp_packet + sizeof(sr_ethernet_hdr_t));

    /* create ICMP header */
    sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_icmp_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

    /*change the src and des based on the previous packet*/
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

    /* set protocol type of IP */
    new_eth_hdr->ether_type = htons(ethertype_ip);

    /*set Ip header*/
    new_ip_hdr->ip_id   = htons(0);
    new_ip_hdr->ip_off  = htons(IP_DF);
    new_ip_hdr->ip_ttl  = 255;
    new_ip_hdr->ip_p    = ip_protocol_icmp;
    new_ip_hdr->ip_v    = 4;
    new_ip_hdr->ip_hl   = sizeof(sr_ip_hdr_t) / 4;
    new_ip_hdr->ip_tos  = 0;
    new_ip_hdr->ip_len  = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

    /* Here need to check whether it is type 3 or type 11*/
    if (code == 3){
        new_ip_hdr->ip_src = ip_hdr->ip_dst;
    }else{
        new_ip_hdr->ip_src = out_interface->ip;
    }

    /* set  IP destination to received packet's source IP */
    new_ip_hdr->ip_dst = ip_hdr->ip_src;

    /*set checksum */
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

    /*set ICMP header*/
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    /*send ICMP packet*/
    send_pkt(sr, new_icmp_packet, new_len, out_interface, longest_prefix_match_entry->gw.s_addr);
    free(new_icmp_packet);

}

/*send_pkt is used to send packet,when we need to send ICMP msg, or rend ARP request/reply.*/
void send_pkt(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* interface, uint32_t dest_ip){
    /*check ARP cache for the next-hop MAC address corresponding to the next-hop IP*/
    struct sr_arpentry* arp_cached_found = sr_arpcache_lookup(&sr->cache, dest_ip);
    if(arp_cached_found) {
        /*there is MAC address, send the packet through the interface*/
        printf("ARP cached found.\n");
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
        /*set the destination MAC address to the found MAC address*/
        memcpy(ethernet_hdr->ether_dhost, arp_cached_found->mac, ETHER_ADDR_LEN);
        /*set the source MAC address to the outgoing interface*/
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, interface->name);
        free(arp_cached_found);
    }else {
        /*can not find the corresponding MAC address in the cache, send ARP request for the next hop*/
        /*add the packet to the queue of the packets waiting on ARP request*/
        printf("Add an ARP request to the ARP request queue\n");
        struct sr_arpreq* arp_req = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
        handle_arpreq(sr, arp_req);
    }
}










