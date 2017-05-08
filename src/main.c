#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <search.h>

#define MAX_COUNT 10000

struct connection {
  u_int8_t         proto;
  struct in_addr   src;
  struct in_addr   dst;
  u_int16_t        port;
  int              count;
};

int compare_connection(const void* a, const void* b) {
  struct connection* con_a = (struct connection*)a;
  struct connection* con_b = (struct connection*)b;

  if(con_a->proto > con_b->proto) {
    return 1;
  }
  else if(con_a->proto < con_b->proto) {
    return -1;
  }
  else if(con_a->src.s_addr > con_b->src.s_addr) {
    return 1;
  }
  else if(con_a->src.s_addr < con_b->src.s_addr) {
    return -1;
  }
  else if(con_a->dst.s_addr > con_b->dst.s_addr) {
    return 1;
  }
  else if(con_a->dst.s_addr < con_b->dst.s_addr) {
    return -1;
  }
  else if(con_a->port > con_b->port) {
    return 1;
  }
  else if(con_a->port < con_b->port) {
    return -1;
  }

  return 0;
}

void action(const void *nodep, const VISIT which, const int depth) {
  struct connection* con;
  switch(which) {
  case postorder:
  case leaf:
    con = *(struct connection**) nodep;
    printf("%-20s ", inet_ntoa(con->src));
    printf("%-20s ", inet_ntoa(con->dst));
    printf("%-5d ", ntohs(con->port));
    if(con->count > MAX_COUNT) {
      printf("(more than %d)\n", MAX_COUNT);
    }
    else {
      printf("%d\n", con->count);
    }
    break;
  default:
    break;
  }
}

int process_package(void** root, const u_char* p, u_int length, u_int caplen) {
  struct ether_header* eptr;
  struct ip* ipptr;
  struct tcphdr* tcpptr;
  struct udphdr* udpptr;
  u_int16_t ether_type = 0;
  struct connection* con = NULL;
  struct connection* found = NULL;

  if(!(ETHER_IS_VALID_LEN(caplen))) {
    fprintf(stderr, "Invalid package length: %d\n", length);
    return -1;
  }


  eptr = (struct ether_header *)p;
  p += ETHER_HDR_LEN;

  ether_type = ntohs(eptr->ether_type);

  if(ether_type != ETHERTYPE_IP) {
    fprintf(stderr, "Only support ip ethernet type\n");
    return -1;
  }

  ipptr = (struct ip*)p;

  switch (ipptr->ip_p) {
    case IPPROTO_TCP:
      p += ipptr->ip_hl * 4;
      tcpptr = (struct tcphdr*)p;

      con = malloc(sizeof(struct connection));
      con->src = ipptr->ip_src;
      con->dst = ipptr->ip_dst;
      con->port = tcpptr->th_dport;
      con->proto = ipptr->ip_p;
      con->count = 1;

      break;
    case IPPROTO_UDP:
      p += ipptr->ip_hl * 4;
      udpptr = (struct udphdr*)p;

      con = malloc(sizeof(struct connection));
      con->src = ipptr->ip_src;
      con->dst = ipptr->ip_dst;
      con->port = udpptr->uh_dport;
      con->proto = ipptr->ip_p;
      con->count = 1;

      break;
    default:
      fprintf(stderr, "Only support TCP and UDP\n");
      break;
  }

  if(con != NULL) {
    found = tsearch(con, root, compare_connection);
    if((*(struct connection**)found) != con) {
      free(con);
      con = *(struct connection**)found;
      if(con->count <= MAX_COUNT) {
        con->count++;
      }
    }
    else {
      printf("New connection ");
      switch (con->proto) {
        case IPPROTO_TCP:
          printf("(TCP): ");
          break;
        case IPPROTO_UDP:
          printf("(UDP): ");
          break;
        default:
          printf("( ? ): ");
          break;
      }
      printf("%16s ->", inet_ntoa(con->src));
      printf("%16s ", inet_ntoa(con->dst));
      printf("Port %5d\n", ntohs(con->port));
    }
    return 0;
  }
  else {
    return 1;
  }
}

int main(int argc, char** argv) {
  char* dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr hdr;
  struct bpf_program filter;
  const u_char* data;
  void* root = NULL;

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(EXIT_FAILURE);
  }

  pcap_t* p = pcap_open_live(dev, 8192, 0, 0, errbuf);


  if(p == NULL) {
    printf("Error while pcap_create: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if(pcap_set_datalink(p, DLT_EN10MB) == -1) {
    fprintf(stderr, "Failed to set link type to ethernet: %s\n", pcap_geterr(p));
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  if(pcap_compile(p, &filter, "((tcp[tcpflags] == tcp-syn) or udp) and not port 53", 1, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Failed to compile filter expression: %s\n", pcap_geterr(p));
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  if(pcap_setfilter(p, &filter) == -1) {
    fprintf(stderr, "Failed to set filter: %s\n", pcap_geterr(p));
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  for(int i=0; i<30; i++) {
    data = pcap_next(p, &hdr);

    if(data == NULL) {
      fprintf(stderr, "Unable to grab packet\n");
      pcap_close(p);
      exit(EXIT_FAILURE);
    }

    process_package(&root, data, hdr.len, hdr.caplen);
  }

  printf("Summary:\n");
  printf("%-20s %-20s %-5s %s\n", "Source", "Destination", "Port", "Times");
  twalk(root, action);
  tdestroy(root, free);


  pcap_close(p);
  return(0);
}
