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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <string.h>
#include <stdlib.h>

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


  uint16_t packet_type = ethertype(packet);

  switch(packet_type)
  {
    case ethertype_arp:
      sr_handle_arp_packet(sr, packet, len, interface);
      break;
    case ethertype_ip:
      sr_handle_ip_packet(sr, packet, len, interface);
      break;
  }

}/* end sr_ForwardPacket */


/************************************************/
/***************** My Code **********************/
/************************************************/


/* handling ARP requests and replies */
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t* packet,
                          unsigned int len, char* interface)
{
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  struct sr_if* receive_interface= sr_get_interface(sr, interface);
/* 
  printf("Handling an ARP frame!!!!! \n");
*/
  uint16_t opcode = ntohs(arp_hdr->ar_op);

  switch(opcode)
  {
    case arp_op_request:
      sr_handle_arp_request(sr, e_hdr, arp_hdr, receive_interface);
      break;
    case arp_op_reply:
      sr_handle_arp_reply(sr, arp_hdr, receive_interface);
      break;
  }

}

/* generate and process ARP request */
void sr_handle_arp_request(struct sr_instance* sr, sr_ethernet_hdr_t* old_e_hdr,
                           sr_arp_hdr_t* old_arp_hdr, struct sr_if* cur_interface)
{
/*  
  printf("We have an ARP request at interfce %s, constructing reply\n", cur_interface->name);
*/  
  /* ready to send reply */
  
  /* create the new packet */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* new_packet = malloc(len);

  sr_ethernet_hdr_t* new_e_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_arp_hdr_t* new_arp_hdr = (sr_arp_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t));

  /* fill in ethernet header, change sr/dest addr, remain arp type */
  new_e_hdr->ether_type = old_e_hdr->ether_type; 
  memcpy(new_e_hdr->ether_dhost, old_e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_shost, cur_interface->addr, ETHER_ADDR_LEN);

  /* fill in arp header, only change sr/dest addr, op type */
  new_arp_hdr->ar_hrd = old_arp_hdr->ar_hrd;
  new_arp_hdr->ar_pro = old_arp_hdr->ar_pro;
  new_arp_hdr->ar_hln = old_arp_hdr->ar_hln;
  new_arp_hdr->ar_pln = old_arp_hdr->ar_pln;
  new_arp_hdr->ar_op = htons(arp_op_reply);  /* change to reply type */
  new_arp_hdr->ar_sip = cur_interface->ip;
  new_arp_hdr->ar_tip = old_arp_hdr->ar_sip;
  memcpy(new_arp_hdr->ar_sha, cur_interface->addr, ETHER_ADDR_LEN);
  memcpy(new_arp_hdr->ar_tha, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);

  /* send the new packet back */
  sr_send_packet(sr, new_packet, len, cur_interface->name);
}

/* generate and process ARP reply */
void sr_handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* old_arp_hdr,
                         struct sr_if* cur_interface)
{ 
  /* check the dest of this ARP replay */
  if (old_arp_hdr->ar_tip == cur_interface->ip)
  {
/*
    printf("\tWe have an ARP reply at interfce %s, caching it and forward\n", cur_interface->name);
*/  
    
    /* Looks up this IP in the request queue. If it is found, returns a pointer
       to the sr_arpreq with this IP. Otherwise, returns NULL. */
    struct sr_arpreq* request = sr_arpcache_insert(&sr->cache, old_arp_hdr->ar_sha, 
                                                   old_arp_hdr->ar_sip);
    
    /* Go into the request queue*/
    if(request)
    {
      struct sr_packet* packet_walker = request->packets;

      /* loop throuh all packet waiting on this replay*/
      while(packet_walker)
      { /* sneding out the waiting packet */
/*       printf("Forwarding a packet that has been waiting for ARP reply\n");
*/
        uint8_t* new_packet = packet_walker->buf;
        sr_ethernet_hdr_t* new_e_hdr = (sr_ethernet_hdr_t*)(new_packet);
        sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet+sizeof(sr_ethernet_hdr_t));
        
        memcpy(new_e_hdr->ether_dhost, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(new_e_hdr->ether_shost, cur_interface->addr, ETHER_ADDR_LEN);

        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

        sr_send_packet(sr, new_packet, packet_walker->len, cur_interface->name);
        
        packet_walker = packet_walker->next;
      }

      /* after send out packets queued waiting for MAC resoluton, 
         drop cur_request from queue*/
      sr_arpreq_destroy(&sr->cache, request);
    }
  }
}

/*****************************************************/
/******************IP PACKET**************************/
/*****************************************************/


/* handling IP packet */
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
                          unsigned int len, char* interface)
{ 
  struct sr_if* receive_interface= sr_get_interface(sr, interface);

  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* check length and checksum */
  if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)))
  {
    printf(" ip packet len is not correct\n");
    return;
  }

  uint16_t temp_ip_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if(temp_ip_sum != cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
  {  
    ip_hdr->ip_sum = temp_ip_sum;
    printf(" ip packet check sum is not correct\n");
    return;
  }
  else
    ip_hdr->ip_sum = temp_ip_sum;
  

  /* check if this packet is for router or not */
  struct sr_if* interface_walker = sr->if_list;

  while(interface_walker)
  { 
    /* if it is for me */
    if(interface_walker->ip == ip_hdr->ip_dst)
    {
      /* check ip packet protocol is ICMP or TCP/UDP */
      if (ip_hdr->ip_p == ip_protocol_icmp)
      {
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

        /* check icmp's cksum */
/*        uint16_t temp_icmp_sum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        if(temp_icmp_sum != cksum(icmp_hdr, (ntohs(len)-sizeof(sr_icmp_hdr_t))))
        {
          icmp_hdr->icmp_sum = temp_icmp_sum;
          printf("the ip packet, icmp header check sum is not correct\n");
          return;
        }
        else
          icmp_hdr->icmp_sum = temp_icmp_sum;
*/          
        
        /* if ICMP request, then send ICMP reply */
        if (icmp_hdr->icmp_type == 0x08)
        {
/*        
          printf("interface %s received icmp request, send reply\n", interface_walker->name);
*/
          struct sr_if* new_interface;

          /* find which interface should we use send out */
          struct sr_rt* rtable_walker = sr->routing_table;
          while(rtable_walker)
          {
            /* Longest prefix match */
            uint32_t dist = rtable_walker->mask.s_addr & ip_hdr->ip_src;
            if(dist == rtable_walker->dest.s_addr)
            {
              new_interface = sr_get_interface(sr, rtable_walker->interface);
            }
            rtable_walker = rtable_walker->next;
          }

          /* change ethernet header */
          memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);

          /* change ip header */
          ip_hdr->ip_dst = ip_hdr->ip_src;
          ip_hdr->ip_src = receive_interface->ip;

          /* change icmp header */
          icmp_hdr->icmp_type = 0x00;    /* this is icmp reply*/
          icmp_hdr->icmp_code = 0x00;
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

          /* send icmp reply back */
          sr_send_packet(sr, packet, len, new_interface->name);
        }
      }
      else   /* is tcp/udp */
      {
        printf("interface %s received tcp/udp, send icmp port unreachable\n", receive_interface->name);
      
        /* send ICMP port unreachable */
        sr_handle_icmp_t3(sr, packet, 0x03, 0x03, receive_interface);
      }
    }
    interface_walker = interface_walker->next;
  }



  /* Not for me */
  
  /* decrement TTL */
  ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
  if (ip_hdr->ip_ttl == 0)
  {
    printf(" Time out!! TTL is 0 now, send ICMP time exceeded\n");

    sr_handle_icmp_t3(sr, packet, 0x11, 0x00, receive_interface);
  }

  /* IP forwarding */

  sr_handle_ip_forwarding(sr, packet, len, receive_interface);
}


void sr_handle_ip_forwarding(struct sr_instance *sr, uint8_t* packet, unsigned int len,
                             struct sr_if* cur_interface)
{
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t));
  
  struct sr_if* new_interface;
  int flag = 0;   /* check if we find dst ip in the rtable */

  /* find which interface should we use send out */
  struct sr_rt* rtable_walker = sr->routing_table;
  while(rtable_walker)
  {
    /* Longest prefix match */
    uint32_t dist = rtable_walker->mask.s_addr & ip_hdr->ip_dst;
    if(dist == rtable_walker->dest.s_addr)
    {
      new_interface = sr_get_interface(sr, rtable_walker->interface);
      flag = 1;
    }
    rtable_walker = rtable_walker->next;
  }

  /* check if we find next interface in routing table */
  if (flag == 1)
  {
     struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

     /* check the ARP cache table */
     if(entry)
     {
       /* send frame to the nexthop */
       memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
       memcpy(e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);

       ip_hdr->ip_sum = 0;
       ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

       sr_send_packet(sr, packet, len, new_interface->name);
       free(entry);
       return;
     }
     else  /* Queue the packet, send ARP request*/
     {
/*       printf("We don't find the receiver IP\n");
*/
       struct sr_arpreq* request = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst,
                                    packet, len, new_interface->name);
/*
       printf("tnew_interface is: %s\n", new_interface->name);
*/       sr_handle_arpreq(sr, request);
       return;
     }
  }
  else   /* No match in rtable, send ICMP network unreachable back */
  {
    printf(" No match in rtable, send ICMP network unreachable back\n");
    sr_handle_icmp_t3(sr, packet, 0x03, 0x00, cur_interface);
  }
}

void sr_handle_icmp_t3(struct sr_instance *sr, uint8_t* old_packet, uint8_t icmp_type,
                       uint8_t icmp_code, struct sr_if* cur_interface)
{

  /* ready to send icmp type 3 error */
  
  /* create the new packet */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t3_hdr_t);
  uint8_t* new_packet = malloc(len);
  
  /* get old header info of ether/ip */
   sr_ethernet_hdr_t* old_e_hdr = (sr_ethernet_hdr_t*)old_packet;
   sr_ip_hdr_t* old_ip_hdr = (sr_ip_hdr_t*)(old_packet+ sizeof(sr_ethernet_hdr_t));

  /* get new header info of ether/ip/icmp type3 */
  sr_ethernet_hdr_t* new_e_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t)
                                                   + sizeof(sr_ip_hdr_t));

  struct sr_if* new_interface;

  /* find which interface should we use send out */
  struct sr_rt* rtable_walker = sr->routing_table;
  while(rtable_walker)
  {
    /* Longest prefix match */
    uint32_t dist = rtable_walker->mask.s_addr & old_ip_hdr->ip_src;
    if(dist == rtable_walker->dest.s_addr)
    {
      new_interface = sr_get_interface(sr, rtable_walker->interface);
    }
    rtable_walker = rtable_walker->next;
   }

  /* fill in ethernet header, change sr/dest addr, remain arp type */
  new_e_hdr->ether_type = old_e_hdr->ether_type;  /* ip type */ 
  memcpy(new_e_hdr->ether_dhost, old_e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);

  /* fill in ip header, change src/dst/sum/len/tll */
  new_ip_hdr->ip_hl = old_ip_hdr->ip_hl;
  new_ip_hdr->ip_v = old_ip_hdr->ip_v;
  new_ip_hdr->ip_tos = old_ip_hdr->ip_tos;
  new_ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  new_ip_hdr->ip_id = old_ip_hdr->ip_id;
  new_ip_hdr->ip_off = old_ip_hdr->ip_off;
  new_ip_hdr->ip_ttl = INIT_TTL;
  new_ip_hdr->ip_p = old_ip_hdr->ip_p;
  new_ip_hdr->ip_src = cur_interface->ip;
  new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  /* fill in icmp type3 header */
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  memcpy(icmp_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /* send the new packet back */
  sr_send_packet(sr, new_packet, len, new_interface->name);
}


