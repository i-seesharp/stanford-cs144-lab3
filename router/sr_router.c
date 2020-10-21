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
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

int run_ip_sanity_check(sr_ip_hdr_t *ip_header) {

  int min_length = 20;
  
  uint16_t received_checksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t true_checksum = cksum(ip_header, ip_header->ip_hl * 4);
  ip_header->ip_sum = received_checksum;
  if(received_checksum != true_checksum) {
      printf("Error: verify_ip: checksum didn't match.\n");
      return -1;
  }
  if(ip_header->ip_len < min_length) {
      printf("Error: verify_ip: IP packet too short.\n");
      return -1;
  }

  return 0;
}

int run_icmp_sanity_check(unsigned char *packet, unsigned int len) {
  
  uint8_t* payload = (packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)payload;

  /* verify the length of header */
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) + (ip_hdr->ip_hl * 4)) {
    printf("Error: verify_icmp: header too short.\n");
    return -1;
  }

  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* verify the checksum */
  uint16_t received_checksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t true_checksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
  icmp_hdr->icmp_sum = received_checksum;
  if(received_checksum != true_checksum) {
    printf("Error: verify_icmp: checksum didn't match.\n");
    return -1;
  }

  return 0;
}

  


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
void send_message_icmp(struct sr_instance *sr, unsigned char *pkt, unsigned int len, unsigned char type, unsigned char code){

    struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr *)pkt;
    struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *)(pkt + sizeof(struct sr_ethernet_hdr));
    struct sr_rt* routing_entry = longest_matching_prefix(sr, ip_header->ip_src);
    if(routing_entry) {
        fprintf(stderr, "Error: routing_entry not found in send_message_icmp");
        return;
    }
    struct sr_if* iface = sr_get_interface(sr, routing_entry->interface);

    switch(type) {
        case icmp_type_echo_reply: {
            memset(ethernet_header->ether_dhost, 0, ETHER_ADDR_LEN);
            memset(ethernet_header->ether_shost, 0, ETHER_ADDR_LEN);

            unsigned int storage;


            storage = ip_header->ip_dst;
            ip_header->ip_dst = ip_header->ip_src;
            ip_header->ip_src = storage;

            struct sr_icmp_hdr *icmp_header;
            icmp_header = (struct sr_icmp_hdr *)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
            icmp_header->icmp_code = code;
            icmp_header->icmp_type = type;

            icmp_header->icmp_sum = 0;
            icmp_header->icmp_sum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));
            
            send_packet(sr, pkt, len, iface, routing_entry->gw.s_addr);
            break;
        }
        case icmp_type_time_exceeded:
        case icmp_type_dest_unreachable: {

            unsigned int new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
            unsigned char *new_packet = malloc(new_len);

            assert(new_packet);

            sr_ethernet_hdr_t* new_eth_hdr = (sr_ethernet_hdr_t*)new_packet;
            sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(struct sr_ip_hdr));

            memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

            new_eth_hdr->ether_type = htons(ethertype_ip);

            new_ip_hdr->ip_v    = 4;
            new_ip_hdr->ip_hl   = sizeof(sr_ip_hdr_t) / 4;
            new_ip_hdr->ip_tos  = 0;
            new_ip_hdr->ip_len  = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            new_ip_hdr->ip_id   = htons(0);
            new_ip_hdr->ip_off  = htons(IP_DF);
            new_ip_hdr->ip_ttl  = 255;
            new_ip_hdr->ip_p    = ip_protocol_icmp;

            new_ip_hdr->ip_src = code == icmp_dest_unreachable_port ? ip_header->ip_dst : iface->ip;
            
            new_ip_hdr->ip_dst = ip_header->ip_src;

            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_header, ICMP_DATA_SIZE);
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            send_packet(sr, new_packet, new_len, iface, routing_entry->gw.s_addr);
            free(new_packet);
            break;
        }
    }
}

void arp_handler(unsigned char *pkt, unsigned int len, char *iface, struct sr_instance *sr){

  struct sr_arp_hdr *header_arp = (struct sr_arp_hdr *)(pkt + sizeof(struct sr_ethernet_hdr));
  if (ntohs(header_arp->ar_hrd) != arp_hrd_ethernet){
    fprintf(stderr, "Error: invalid ethernet data");
    return;
  }

  if(ntohs(header_arp->ar_pro) != ethertype_ip){
    fprintf(stderr, "Error: invalid protocol");
  }

  struct sr_if *going_iface;
  going_iface = sr_get_interface_by_ip(sr, header_arp->ar_tip);
  if(going_iface){
    fprintf(stderr, "Error: outgoing interface error in  arp handler");
  }

  if(ntohs(header_arp->ar_op) == arp_op_request){
    struct sr_if *coming_iface = sr_get_interface(sr, iface);

    unsigned char *request_arp = malloc(len);
    memcpy(request_arp, pkt, len);
    struct sr_ethernet_hdr *request_ethernet_header = (struct sr_ethernet_hdr *)request_arp;
    memcpy(request_ethernet_header->ether_dhost, request_ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(request_ethernet_header->ether_shost, coming_iface, ETHER_ADDR_LEN);

    struct sr_arp_hdr *request_arp_header = (struct sr_arp_hdr *)(request_arp + sizeof(struct sr_ethernet_hdr));
    request_arp_header->ar_op = htons(arp_op_reply);
    memcpy(request_arp_header->ar_sha, coming_iface->addr, ETHER_ADDR_LEN);
    request_arp_header->ar_sip = coming_iface->ip;
    memcpy(request_arp_header->ar_tha, header_arp->ar_sha, ETHER_ADDR_LEN);
    request_arp_header->ar_tip = header_arp->ar_sip;

    send_packet(sr, request_arp, len, coming_iface, header_arp->ar_sip);
    free(request_arp);

  }

  else if(ntohs(header_arp->ar_op) == arp_op_reply){
    struct sr_arpreq *arp_cached = sr_arpcache_insert(&sr->cache, header_arp->ar_sha, header_arp->ar_sip);
    if(arp_cached){
      struct sr_ethernet_hdr *ethernet_header;
      struct sr_packet *pkt = arp_cached->packets;
      struct sr_if *coming_iface;
      while(pkt){
        coming_iface = sr_get_interface(sr, pkt->iface);
        if(coming_iface){
          ethernet_header = (sr_ethernet_hdr_t*)(pkt->buf);
          memcpy(ethernet_header->ether_shost, coming_iface->addr, ETHER_ADDR_LEN);
          memcpy(ethernet_header->ether_dhost, header_arp->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
        }
        pkt = pkt->next;
      }
      sr_arpreq_destroy(&sr->cache, arp_cached);
    }
  }


}




void ip_handler(unsigned char *pkt, unsigned int len, char *interface, struct sr_instance *sr){

    unsigned char* msg = (pkt + sizeof(struct sr_ethernet_hdr));
    struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *) msg;

    int sanity_check = run_ip_sanity_check(ip_header);
    if(sanity_check < 0) {
        return;
    }

    if(sr_get_interface_by_ip(sr, ip_header->ip_dst)){
        switch(ip_header->ip_p) {
            case ip_protocol_icmp: {
                if(run_icmp_sanity_check(pkt, len) < 0) {
                    return;
                }
                struct sr_icmp_hdr *icmp_header;
                icmp_header = (struct sr_icmp_hdr*)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
                if(icmp_header->icmp_type == icmp_type_echo_request) {
                    send_message_icmp(sr, pkt, len, icmp_type_echo_reply, (unsigned char)0);
                }

                break;
            }
            case ip_protocol_udp:
            case ip_protocol_tcp: {
                send_message_icmp(sr, pkt, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
                break;
            }
        }
    } else {

        struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *)(pkt + sizeof(struct sr_ethernet_hdr));

        ip_header->ip_ttl = ip_header->ip_ttl - 1;
        if(ip_header->ip_ttl < 1) {
            send_message_icmp(sr, pkt, len, icmp_type_time_exceeded, (unsigned char)0);
            return;
        }

        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));

        struct sr_rt* table_entry = longest_matching_prefix(sr, ip_header->ip_dst);
        if(!table_entry) {
            send_message_icmp(sr, pkt, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
            return;
        }

        struct sr_if* going_interface = sr_get_interface(sr, table_entry->interface);
        if(going_interface) {
            fprintf(stderr, "Error: interface not found in handle_ip");
            return;
        }

        send_packet(sr, pkt, len, going_interface, table_entry->gw.s_addr);
    }
}

void send_packet(struct sr_instance *sr, unsigned char *pkt, unsigned int len, struct sr_if *iface, uint32_t ip_destination){
  struct sr_arpentry *cached_arp = sr_arpcache_lookup(&sr->cache, ip_destination);

  if(cached_arp){
    struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr *) pkt;
    memcpy(ethernet_header->ether_dhost, cached_arp->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, pkt, len, iface->name);
    free(cached_arp);

  }
  else{
    struct sr_arpreq *arp_request;
    arp_request = sr_arpcache_queuereq(&sr->cache, ip_destination, pkt, len, iface->name);


    handle_arpreq(arp_request, sr);
  }
}

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

  if (len < sizeof(struct sr_ethernet_hdr)){
    fprintf(stderr, "Error: sr_handlepacket len < size of sr_ethernet head");
  }

  if(ethertype(packet) == ethertype_arp){
    arp_handler(packet, len, interface, sr);
  }
  else if(ethertype(packet) == ethertype_ip){
    ip_handler(packet, len, interface, sr);
  }

}/* end sr_ForwardPacket */



