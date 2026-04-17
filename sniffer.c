#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>  // Ethernet headers
#include <netinet/ip.h>         // IP headers  
#include <netinet/tcp.h>        // TCP headers
#include <netinet/udp.h>        // UDP headers
#include <arpa/inet.h>          // IP address conversion

// Function to print MAC address from 6 bytes
void print_mac(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main() {
    int raw_socket;
    unsigned char *buffer = (unsigned char *)malloc(65536);  // Store packet
    int data_size;
    
    // Pointers to each protocol header
    struct ethhdr *eth;      // Ethernet header
    struct iphdr *ip;        // IP header
    struct tcphdr *tcp;      // TCP header
    struct udphdr *udp;      // UDP header
    
    // Create raw socket to capture all packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (raw_socket < 0) {
        printf("ERROR: Run with sudo!\n");
        return 1;
    }
    
    printf("\n=== RAW PACKET SNIFFER ===\n");
    printf("Capturing packets... Press Ctrl+C to stop\n\n");
    
    while (1) {
        // Capture packet
        data_size = recvfrom(raw_socket, buffer, 65536, 0, NULL, NULL);
        
        if (data_size > 0) {
            // ETHERNET LAYER (starts at byte 0)
            eth = (struct ethhdr *)buffer;
            
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            printf("[ETHERNET]\n");
            printf("  Source MAC:      ");
            print_mac(eth->h_source);
            printf("\n  Destination MAC: ");
            print_mac(eth->h_dest);
            printf("\n");
            
            // Check if packet is IP (0x0800 = IPv4)
            if (ntohs(eth->h_proto) == ETH_P_IP) {
                
                // IP LAYER (starts after Ethernet header - 14 bytes)
                ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                
                printf("[IP]\n");
                
                // Convert IP addresses to readable strings
                struct sockaddr_in source, dest;
                source.sin_addr.s_addr = ip->saddr;
                dest.sin_addr.s_addr = ip->daddr;
                
                printf("  Source IP:       %s\n", inet_ntoa(source.sin_addr));
                printf("  Destination IP:  %s\n", inet_ntoa(dest.sin_addr));
                printf("  TTL (Time To Live): %d\n", ip->ttl);
                printf("  Protocol:        %d ", ip->protocol);
                
                // TRANSPORT LAYER (TCP or UDP)
                // TCP protocol = 6
                if (ip->protocol == 6) {
                    printf("(TCP)\n");
                    // TCP header starts after IP header (ip->ihl * 4 = header length in bytes)
                    tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
                    printf("[TCP]\n");
                    printf("  Source Port:     %d\n", ntohs(tcp->source));
                    printf("  Destination Port:%d\n", ntohs(tcp->dest));
                    
                    // Show TCP flags (SYN, ACK, FIN, etc.)
                    printf("  TCP Flags:       ");
                    if (tcp->syn) printf("SYN ");
                    if (tcp->ack) printf("ACK ");
                    if (tcp->fin) printf("FIN ");
                    if (tcp->rst) printf("RST ");
                    printf("\n");
                }
                // UDP protocol = 17
                else if (ip->protocol == 17) {
                    printf("(UDP)\n");
                    // UDP header starts after IP header
                    udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
                    printf("[UDP]\n");
                    printf("  Source Port:     %d\n", ntohs(udp->source));
                    printf("  Destination Port:%d\n", ntohs(udp->dest));
                    printf("  Length:          %d bytes\n", ntohs(udp->len));
                }
                else {
                    printf("(Other)\n");
                }
            }
            else {
                printf("[NON-IP PACKET] Type: 0x%04x\n", ntohs(eth->h_proto));
            }
            
            printf("  Total Size:      %d bytes\n", data_size);
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        }
    }
    
    free(buffer);
    close(raw_socket);
    return 0;
}
