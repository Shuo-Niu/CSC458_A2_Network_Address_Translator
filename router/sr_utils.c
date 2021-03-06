#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}

/* Custom method: convert IP int to string */
/* Basically modified from 'print_addr_ip_int' above */
void addr_ip_int(char* buf, uint32_t ip) {
    sprintf(
        buf,
        "%d.%d.%d.%d",
        ip >> 24,
        (ip << 8) >> 24,
        (ip << 16) >> 24,
        (ip << 24) >> 24
    );
}

/* Custom method: sanity-check IP packet */
int verify_ip(sr_ip_hdr_t* ip_hdr) {
  /* store the received checksum */
  uint16_t received_checksum = ip_hdr->ip_sum;
  /* make checksum zero to calculate the true checksum */
  ip_hdr->ip_sum = 0;
  uint16_t true_checksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  ip_hdr->ip_sum = received_checksum;
  /* compare the received checksum and the value it should be */
  if(received_checksum != true_checksum) {
      printf("Error: verify_ip: checksum didn't match.\n");
      return -1;
  }
  /* verify the length of IP packet */
  if(ip_hdr->ip_len < 20) {
      printf("Error: verify_ip: IP packet too short.\n");
      return -1;
  }

  return 0;
}

/* Custom method: sanity-check ICMP packet */
int verify_icmp(uint8_t* packet, unsigned int len) {
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

/* Custom method: calculate TCP checksum */
uint16_t tcp_hdr_cksum(void* packet, unsigned int len) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
  int pseudo_tcp_len = sizeof(sr_pseudo_tcp_hdr_t) + tcp_len;

  /* construct pseudo TCP header */
  sr_pseudo_tcp_hdr_t *pseudo_tcp_hdr = (sr_pseudo_tcp_hdr_t*)malloc(pseudo_tcp_len);
  pseudo_tcp_hdr->ip_src = ip_hdr->ip_src;
  pseudo_tcp_hdr->ip_dst = ip_hdr->ip_dst;
  pseudo_tcp_hdr->reserved = 0;
  pseudo_tcp_hdr->ip_p = ip_protocol_tcp;
  pseudo_tcp_hdr->tcp_len = htons(tcp_len);
  memcpy((uint8_t*)pseudo_tcp_hdr + sizeof(sr_pseudo_tcp_hdr_t), (uint8_t*)tcp_hdr, tcp_len);

  /* calculate checksum */
  uint16_t checksum = cksum(pseudo_tcp_hdr, pseudo_tcp_len);

  free(pseudo_tcp_hdr);
  return checksum;
}

/* Custom method: sanity-check TCP packet */
int verify_tcp(uint8_t *packet, unsigned int len) {
  uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)payload;

  /* verify the length of header */
  if(tcp_hdr->offset < 5) {
    printf("Error: verify_tcp: header too short.\n");
    return -1;
  }

  /* verify the checksum */
  uint16_t received_checksum = tcp_hdr->checksum;
  tcp_hdr->checksum = 0;
  uint16_t true_checksum = tcp_hdr_cksum(packet, len);
  tcp_hdr->checksum = received_checksum;
  if(received_checksum != true_checksum) {
    printf("Error: verify_tcp: checksum didn't match.\n");
    return -1;
  }

  return 0;
}

/* Custom method: prints out fields in TCP header */
/* modified from provided 'print_hdr_ip()' */
void print_hdr_tcp(uint8_t *buf) {
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t*)buf;
  fprintf(stderr, "TCP header:\n");
  fprintf(stderr, "\tsource port: %d\n", ntohs(tcphdr->src_port));
  fprintf(stderr, "\tdestination port: %d\n", ntohs(tcphdr->dst_port));
  fprintf(stderr, "\tsequence number: %d\n", ntohs(tcphdr->seq));
  fprintf(stderr, "\tacknowledgment: %d\n", ntohs(tcphdr->ack));
  fprintf(stderr, "\toffset: %d\n", ntohs(tcphdr->offset));

  fprintf(stderr, "\tCWR: %d\n", tcphdr->cwr);
  fprintf(stderr, "\tECE: %d\n", tcphdr->ece);
  fprintf(stderr, "\tURG: %d\n", tcphdr->urg);
  fprintf(stderr, "\tACK: %d\n", tcphdr->ack);
  fprintf(stderr, "\tPSH: %d\n", tcphdr->psh);
  fprintf(stderr, "\tRST: %d\n", tcphdr->rst);
  fprintf(stderr, "\tSYN: %d\n", tcphdr->syn);
  fprintf(stderr, "\tFIN: %d\n", tcphdr->fin);

  fprintf(stderr, "\twindow size: %d\n", tcphdr->window_size);
  fprintf(stderr, "\tchecksum: %d\n", tcphdr->checksum);
  fprintf(stderr, "\turgent pointer: %d\n", tcphdr->urgent);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    } 
    /* modified from ==ip_protocol_icmp above */
    else if(ip_proto == ip_protocol_tcp) { /* TCP */
      minlength += sizeof(sr_tcp_hdr_t);
      if(length < minlength)
        fprintf(stderr, "Failed to print TCP header, insufficient length\n");
      else
        print_hdr_tcp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

