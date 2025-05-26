#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h> // struct ether_header
#include <pcap.h>

void handle_packet(const u_char *packet)
{
    const struct ether_header *eth_hdr = (struct ether_header *)packet;

    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
           eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
           eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
           eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
           eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
}
