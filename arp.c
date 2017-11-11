#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{}
void set_op_code(struct ether_arp *packet, short int code)
{}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char *result = malloc(7 * sizeof(char));

    result[0] = packet->arp_tpa[0];
    result[1] = '.';
    result[2] = packet->arp_tpa[1];
    result[3] = '.';
    result[4] = packet->arp_tpa[2];
    result[5] = '.';
    result[6] = packet->arp_tpa[3];

    return result;

}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	unsigned char *result = malloc(7 * sizeof(char));

	result[0] = packet->arp_spa[0];
    result[1] = '.';
    result[2] = packet->arp_spa[1];
    result[3] = '.';
    result[4] = packet->arp_spa[2];
    result[5] = '.';
    result[6] = packet->arp_spa[3];

    return result;
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char *result = malloc(11 * sizeof(char));

	//mac_no
	result[0] = packet->arp_sha[0];
    result[1] = ':';
    result[2] = packet->arp_sha[1];
    result[3] = ':';
    result[4] = packet->arp_sha[2];
    result[5] = ':';
    result[6] = packet->arp_sha[3];
    result[7] = ':';
    result[8] = packet->arp_sha[4];
    result[9] = ':';
    result[10] = packet->arp_sha[5];

    return result;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char *result = malloc(11 * sizeof(char));

	result[0] = packet->arp_tha[0];
    result[1] = ':';
    result[2] = packet->arp_tha[1];
    result[3] = ':';
    result[4] = packet->arp_tha[2];
    result[5] = ':';
    result[6] = packet->arp_tha[3];
    result[7] = ':';
    result[8] = packet->arp_tha[4];
    result[9] = ':';
    result[10] = packet->arp_tha[5];

    return result;
}
