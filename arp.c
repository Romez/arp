#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define PROTO_ARP 0x0806
#define PROTO_IPV4 0x0800
#define HW_TYPE 1
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

#define MAC_LEN 6
#define IPV4_LEN 4

const unsigned char broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

typedef struct
{
    uint16_t hardware_type;     /* 1 */
    uint16_t protocol_type;     /* 0x0806 */
    uint8_t hardware_len;       /* MAC address byte length */
    uint8_t protocol_len;       /* IPv4 address byte length */
    uint16_t opcode;            /* ARP_REQUEST or ARP_REPLY */
    uint8_t sender_mac[MAC_LEN];
    uint8_t sender_ip[IPV4_LEN];
    uint8_t target_mac[MAC_LEN];
    uint8_t target_ip[IPV4_LEN];
} ArpPack;

typedef struct {
    struct ethhdr eth_hdr;
    ArpPack arp_pack;
} EthFrame;

void print_mac(const unsigned char* mac) {
    printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const unsigned char* ip) {
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

int get_interface_idx(int sock, char* in_name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, in_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl SIOCGIFINDEX");
        exit(1);
    }

    return ifr.ifr_ifindex;
}

void get_interface_mac(int sock, char* in_name, unsigned char* mac) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, in_name, IFNAMSIZ - 1);

    // get interface mac
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFHWADDR");
        exit(1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
}

void get_interface_ip(int sock, char* in_name, unsigned char* ip) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, in_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr)) {
        perror("ioctl SIOCGIFADDR");
        exit(1);
    }

    // unsigned char ip[IPV4_LEN];
    memcpy(ip, (unsigned char*)&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IPV4_LEN);
}

ArpPack build_arp_pack(unsigned char sender_ip[IPV4_LEN], unsigned char sender_mac[MAC_LEN], const char* target_ip) {
    ArpPack arp_pack;

    memset(&arp_pack, 0, sizeof(arp_pack));

    arp_pack.hardware_type = htons(HW_TYPE);
    arp_pack.protocol_type = htons(PROTO_IPV4);
    arp_pack.hardware_len = MAC_LEN;
    arp_pack.protocol_len = IPV4_LEN;
    arp_pack.opcode = htons(ARP_REQUEST);

    memcpy(arp_pack.sender_mac, sender_mac, MAC_LEN);
    memcpy(arp_pack.sender_ip, sender_ip, IPV4_LEN);
    inet_pton(AF_INET, target_ip, arp_pack.target_ip);
    memset(arp_pack.target_mac, 0, MAC_LEN);

    return arp_pack;
}

struct ethhdr build_eth_hdr(const unsigned char src_mac[MAC_LEN], const unsigned char dest_mac[MAC_LEN], const uint16_t proto) {
    struct ethhdr eth_hdr;
    memset(&eth_hdr, 0, sizeof(eth_hdr));
    eth_hdr.h_proto = htons(proto);
    memcpy(eth_hdr.h_dest, dest_mac, MAC_LEN);
    memcpy(eth_hdr.h_source, src_mac, MAC_LEN);
    return eth_hdr;
}

unsigned char* get_arp(char* target_ip) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock == -1) {
        perror("arp socket");
        exit(1);
    }

    char* if_name = "wlo1";
    int ifindex = get_interface_idx(sock, if_name);

    unsigned char mac[MAC_LEN];
    get_interface_mac(sock, if_name, mac);

    unsigned char ip[IPV4_LEN];
    get_interface_ip(sock, if_name, ip);

    // printf("wlo1 index: %d\n", ifindex);
    // print_mac(mac);
    // print_ip(ip);

    // Ethernet header
    struct ethhdr eth_hdr = build_eth_hdr(mac, broadcast_addr, ETH_P_ARP);

    // Arp packet
    ArpPack arp_pack = build_arp_pack(ip, mac, target_ip);

    // print_mac(arp_pack.sender_mac);
    // print_ip(arp_pack.sender_ip);

    EthFrame arp_frame = {
        .eth_hdr = eth_hdr,
        .arp_pack = arp_pack,
    };

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = htons(AF_PACKET),
    sa.sll_protocol = htons(ETH_P_ARP),
    sa.sll_ifindex = ifindex,
    sa.sll_hatype = htons(ARPHRD_ETHER),
    sa.sll_pkttype = PACKET_BROADCAST,
    sa.sll_halen = MAC_LEN,

    memcpy(sa.sll_addr, broadcast_addr, MAC_LEN);
    // print_mac(sa.sll_addr);

    if (sendto(sock, &arp_frame, sizeof(arp_frame), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("sendto");
        exit(1);
    }

    EthFrame arp_resp;

    ssize_t recv_bytes = recvfrom(sock, &arp_resp, sizeof(EthFrame), 0, NULL, 0);
    if (recv_bytes == -1) {
        perror("recvfrom");
        exit(1);
    }

    close(sock);

    unsigned char* target_mac = malloc(MAC_LEN);
    if (target_mac == NULL) {
	perror("malloc mac");
	exit(1);
    }
    memcpy(target_mac, arp_resp.arp_pack.sender_mac, MAC_LEN);

    return target_mac;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: arp 192.168.0.10\n");
        exit(1);
    }

    char* target_ip = argv[1];
    unsigned char* mac = get_arp(target_ip);

    print_mac(mac);

    return 0;
}
