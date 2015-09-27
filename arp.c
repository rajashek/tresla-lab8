#include<stdio.h>
#include <net/ethernet.h>
#include<stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <signal.h>

#define DEVICE1 "eth2"
#define DEVICE2 "eth3"
#define IP_ADDR1 "10.10.1.2"
#define IP_ADDR2 "10.1.2.1"
#define IP_ADDR3 "10.1.2.3"
#define IP_ADDR4 "10.1.2.4"

#define ETHER_TYPE_FOR_ARP 0x0806
#define HW_TYPE_FOR_ETHER 0x0001
#define OP_CODE_FOR_ARP_REQ 0x0001
#define HW_LEN_FOR_ETHER 0x06
#define HW_LEN_FOR_IP 0x04
#define PROTO_TYPE_FOR_IP 0x0800

#define BUF_SIZE 42
#define SIZE_ETHERNET 14
int MAC_MAP [4]={0};
struct ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
struct __attribute__((packed)) arp_packet
{
    unsigned short arp_hd;
    unsigned short arp_pr;
    unsigned char arp_hdl;
    unsigned char arp_prl;
    unsigned short arp_op;
    unsigned char arp_sha[6];
    unsigned long arp_spa;
    unsigned char arp_dha[6];
    unsigned long arp_dpa;
};
struct arp_table{
	unsigned long ip_addr;
	u_char  ether_dhost[ETHER_ADDR_LEN];
};
struct linkedlist{
	struct arp_table table;
	struct linkedlist* next;
};

struct linkedlist *root;
void init_list(struct arp_table *arp){
	struct linkedlist* new_node = NULL;
	struct linkedlist* cur_node = NULL;
	new_node = (struct linkedlist*)malloc(sizeof(struct linkedlist));
	if (new_node==NULL){
		printf("\n Malloc failed \n");
		return;
	}
	new_node->next = NULL;
	new_node->table.ip_addr = arp->ip_addr;
	new_node->table.ether_dhost[0] = arp->ether_dhost[0];
	new_node->table.ether_dhost[1] = arp->ether_dhost[1];
	new_node->table.ether_dhost[2] = arp->ether_dhost[2];
	new_node->table.ether_dhost[3] = arp->ether_dhost[3];
	new_node->table.ether_dhost[4] = arp->ether_dhost[4];
	new_node->table.ether_dhost[5] = arp->ether_dhost[5];
	if (root==NULL){
		root = new_node;
	}
	else{
		cur_node = root;
		while(cur_node->next!=NULL)
			cur_node=cur_node->next;
		cur_node->next = new_node;
	}
 

}

unsigned char * get_mac_address(char *ipaddress){
	struct linkedlist* cur_node = NULL;
	if(root==NULL){
		printf("MAC table empty \n ");
	}	
	cur_node = root;
	while (cur_node!=NULL){
		printf("node ip %lu\n",cur_node->table.ip_addr);	
		if (strcmp(inet_ntoa(cur_node->table.ip_addr),ipaddress)==0){
			return cur_node->table.ether_dhost;
		}
		cur_node = cur_node->next;
	}	

}
int init_src_mac(char *device,struct arp_table *arp){
	struct ifreq ifr;
	int arp_socket = -1;
	arp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    	if (arp_socket== -1) {
        	perror("socket():");
        	exit(1);
    	}
	int ifindex = 0; 
	printf("Device %s\n", device);
	strcpy(ifr.ifr_name, device);
    	if (ioctl(arp_socket, SIOCGIFINDEX, &ifr) == -1) {
        	perror("SIOCGIFINDEX");
        	exit(1);
    	}
    	ifindex = ifr.ifr_ifindex;
   	printf("Successfully got interface index: %i\n", ifindex);  
	/*retrieve corresponding MAC*/
    	if (ioctl(arp_socket, SIOCGIFHWADDR, &ifr) == -1) {
        	perror("SIOCGIFINDEX");
        	exit(1);
    	}
	int i;
	if (strcmp(device,DEVICE1)==0)
		arp->ip_addr = inet_addr(IP_ADDR1);
    	else
		arp->ip_addr = inet_addr(IP_ADDR2);
		
	for (i = 0; i < 6; i++) {
        	arp->ether_dhost[i] = ifr.ifr_hwaddr.sa_data[i];
    	}
	init_list(arp);
	return ifindex;
}
int get_arp_address(){
	int arp_fd = -1;
	struct ifreq ifr;
	void* arp_buffer = NULL;
	arp_buffer = (void*)malloc(BUF_SIZE);
	struct ethernet *eth_head;
	/* define ethernet header */
        eth_head = (struct ethernet*)(arp_buffer); 
	struct arp_packet* arp_head;
	arp_head = (struct arp_packet*)(arp_buffer + SIZE_ETHERNET);
    	struct arp_header *ah;
    	unsigned char src_mac[6];
    	struct sockaddr_ll socket_address;
    	struct arp_table arp;
	struct sockaddr_ll sa; 
    	struct arp_table *arp1=&arp; 
	int i;	
	int rvalue=-1;
	int ifindex;
	ifindex = init_src_mac(DEVICE1,arp1);
    	printf("Successfully got our MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
        arp1->ether_dhost[0],arp1->ether_dhost[1],arp1->ether_dhost[2],arp1->ether_dhost[3],arp1->ether_dhost[4],arp1->ether_dhost[5]);
	if (ifindex>0)
		MAC_MAP[0]=1;
	rvalue = -1;
	ifindex = init_src_mac(DEVICE2,arp1);
	if (ifindex>0)
		MAC_MAP[1]=1;
    	printf("Successfully got our MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
        arp1->ether_dhost[0],arp1->ether_dhost[1],arp1->ether_dhost[2],arp1->ether_dhost[3],arp1->ether_dhost[4],arp1->ether_dhost[5]);
	arp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if( arp_fd == -1 )
	{
		perror("ARP Socket");
		exit(1);
	
	}
	/*Ethernet header*/
	memset(eth_head->ether_dhost, 0xFF, (6 * sizeof(unsigned char)));
	for (i = 0; i < 6; i++) {
                eth_head->ether_shost[i] = arp1->ether_dhost[i];
        }
	eth_head->ether_type = htons(ETHER_TYPE_FOR_ARP); 
	/*Arp header*/
	arp_head->arp_hd = htons(HW_TYPE_FOR_ETHER);
	arp_head->arp_pr = htons(PROTO_TYPE_FOR_IP);
	arp_head->arp_hdl = HW_LEN_FOR_ETHER;
	arp_head->arp_prl = HW_LEN_FOR_IP;
	arp_head->arp_op = htons(OP_CODE_FOR_ARP_REQ);
	memcpy(arp_head->arp_sha, arp1->ether_dhost, (6 * sizeof(unsigned char)));
	arp_head->arp_spa = arp1->ip_addr;
	memset(arp_head->arp_dha, 0 , (6 * sizeof(unsigned char)));
	arp_head->arp_dpa = inet_addr(IP_ADDR3);
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifindex;
	printf("\n interface index %d",sa.sll_ifindex);
	sa.sll_protocol = htons(ETH_P_ARP);
	/* Send it! */
	rvalue = sendto(arp_fd, arp_buffer, BUF_SIZE, 0,(struct sockaddr *)&sa, sizeof(sa));
	if( rvalue < 0 )
	{
		perror("sendto");
		close(arp_fd);
		exit(1);
	}
	printf("\n return value %d ",rvalue);
	return 0;
}
int main (){
	/*unsigned char *ether_shost;
	unsigned long ipaddress = inet_addr("10.1.2.2");
	struct arp_table arp;
	arp.ip_addr = ipaddress;
	arp.ether_dhost[0]=0x00;
        arp.ether_dhost[1]=0x15;
        arp.ether_dhost[2]=0x17;
        arp.ether_dhost[3]=0x57;
        arp.ether_dhost[4]=0xbe;
        arp.ether_dhost[5]=0xa0;
	init_list(arp);
	ipaddress = inet_addr("10.1.2.3");
	arp.ip_addr = ipaddress;
	arp.ether_dhost[0]=0x01;
        arp.ether_dhost[1]=0x15;
        arp.ether_dhost[2]=0x17;
        arp.ether_dhost[3]=0x57;
        arp.ether_dhost[4]=0xbe;
        arp.ether_dhost[5]=0xa0;
	init_list(arp);
	ether_shost = get_mac_address("10.1.2.2");
	printf("         Modified Destination Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ether_shost[0],
                                                                        (unsigned char)ether_shost[1],
                                                                        (unsigned char)ether_shost[2],
                                                                        (unsigned char)ether_shost[3],
                                                                        (unsigned char)ether_shost[4],
                                                                        (unsigned char)ether_shost[5]);	
	ether_shost = get_mac_address("10.1.2.3");
	printf("         Modified Destination Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ether_shost[0],
                                                                        (unsigned char)ether_shost[1],
                                                                        (unsigned char)ether_shost[2],
                                                                        (unsigned char)ether_shost[3],
                                                                        (unsigned char)ether_shost[4],
                                                                        (unsigned char)ether_shost[5]);	*/
	
	root = NULL;
	get_arp_address();
	return 0;
}
