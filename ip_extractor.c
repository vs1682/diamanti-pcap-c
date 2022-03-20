#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCAP_BUF_SIZE 1024

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet);

int main(int argc, char** argv) {
  pcap_t* fp;
  char errbuf[PCAP_ERRBUF_SIZE];
  char source[PCAP_BUF_SIZE];

  if (argc != 2) {
    printf("usage: %s filename\n", argv[0]);
    return -1;
  }

  /*fp = pcap_open_offline_with_tstamp_precision(argv[0],
   * PCAP_TSTAMP_PRECISION_NANO, errbuf);*/
  fp = pcap_open_offline(argv[1], errbuf);
  if (fp == NULL) {
    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
    return 0;
  }

  if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
    fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
    return 0;
  }

  return 0;
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  const struct ip* iph;
  const struct ip6_hdr* ip6h;
  const struct ether_header* eth;
  // Get the IP Header part of this packet , excluding the ethernet header
  eth = (struct ether_header*)packet;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    iph = (struct ip*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(iph->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), destIP, INET_ADDRSTRLEN);
    printf("\n");
    printf("IPv4 Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int)iph->ip_v);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",
           (unsigned int)iph->ip_hl, ((unsigned int)(iph->ip_hl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)iph->ip_tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
           ntohs(iph->ip_len));
    printf("   |-Identification    : %d\n", ntohs(iph->ip_id));
    printf("   |-TTL               : %d\n", (unsigned int)iph->ip_ttl);
    printf("   |-Protocol          : %d\n", (unsigned int)iph->ip_p);
    printf("   |-Checksum          : %d\n", ntohs(iph->ip_sum));
    printf("   |-Source IP         : %s\n", sourceIP);
    printf("   |-Destination IP    : %s\n", destIP);
  }

  if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) {
    char sourceIP[INET6_ADDRSTRLEN];
    char destIP[INET6_ADDRSTRLEN];
    ip6h = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET6, &(ip6h->ip6_src), sourceIP, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6h->ip6_dst), destIP, INET6_ADDRSTRLEN);
    printf("\n");
    printf("IPv6 Header\n");
    printf("   |-IP Version        : %d\n", 6);
    printf("   |-Traffic Class     : 0x%x\n",
           (ntohs(ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff0));
    printf("   |-Flow Label        : 0x%x\n",
           (ntohl(ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
    printf("   |-Payload Length    : %d\n",
           ntohs(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen));
    printf("   |-Hop Limit         : %d\n",
           (unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    printf("   |-Next Header       : %d\n",
           (unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    printf("   |-Source IP         : %s\n", sourceIP);
    printf("   |-Destination IP    : %s\n", destIP);
  }
}