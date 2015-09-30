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
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>

#define APP_NAME "arp"
#define ETHER_TYPE_FOR_ARP 0x0806
#define HW_TYPE_FOR_ETHER 0x0001
#define OP_CODE_FOR_ARP_REQ 0x0001
#define HW_LEN_FOR_ETHER 0x06
#define HW_LEN_FOR_IP 0x04
#define PROTO_TYPE_FOR_IP 0x0800

#define BUF_SIZE 42
#define SIZE_ETHERNET 14
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
void
print_usage(void)
{

        printf("Usage: %s [device][interface]\n", APP_NAME);
        printf("\n");
        printf("Options:\n");
        printf("    interface    IP address of <interface> for MAC address\n");
        printf("    device interface   IP address to send ARP packets\n");
        printf("\n");

return;
}

unsigned char *get_arp_address(char *ip_address, char *device);
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

unsigned char *get_mac_address(char *ip_address){
	struct linkedlist* cur_node = NULL;
	unsigned char *mac_address=(unsigned char *) malloc (sizeof(unsigned char)*6);
	memset(mac_address,0,sizeof(unsigned char)*6);
	if(root==NULL){
		printf("MAC table empty \n ");
	}
	cur_node = root;
	while (cur_node!=NULL){
		printf("node ip %lu\n",cur_node->table.ip_addr);	
		if (strcmp(inet_ntoa(cur_node->table.ip_addr),ip_address)==0){
			memcpy(mac_address, cur_node->table.ether_dhost, (6 * sizeof(unsigned char)));
			printf("TARGET in get mac MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               mac_address[0],
                               mac_address[1],
                               mac_address[2],
                               mac_address[3],
                               mac_address[4],
                               mac_address[5]
                        );
			return mac_address;
		}
		cur_node = cur_node->next;
	}
	return NULL;	

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
    		close(arp_socket);
        	perror("SIOCGIFINDEX");
        	exit(1);
    	}
    	ifindex = ifr.ifr_ifindex;
   	printf("Successfully got interface index: %i\n", ifindex);  
	/*retrieve corresponding MAC*/
    	if (ioctl(arp_socket, SIOCGIFHWADDR, &ifr) == -1) {
    		close(arp_socket);
        	perror("SIOCGIFINDEX");
        	exit(1);
    	}
	int i;
	for (i = 0; i < 6; i++) {
        	arp->ether_dhost[i] = ifr.ifr_hwaddr.sa_data[i];
    	}
	if (ioctl(arp_socket,SIOCGIFADDR,&ifr)==-1) {
    		close(arp_socket);
    		printf("%s\n",strerror(errno));
		exit(1);
	}
	unsigned long addr;
	addr = ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr.s_addr;
	arp->ip_addr = addr;		
	init_list(arp);
	close(arp_socket);
	return ifindex;
}
unsigned char *get_arp_address(char *ip_address, char *device){
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
	struct sockaddr_ll sa; 
    	struct arp_table *arp1=(struct arp_table *)malloc(sizeof(struct arp_table));
	unsigned char *mac_address = (unsigned char *)malloc(6); 
	int i;	
	int rvalue=-1;
	int ifindex;
	ifindex = init_src_mac(device,arp1);
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
	//memcpy(arp_head->arp_sha, arp1->ether_dhost, (6 * sizeof(unsigned char)));
	for (i = 0; i < 6; i++) {
               arp_head->arp_sha[i] = arp1->ether_dhost[i];
        }
	arp_head->arp_spa = arp1->ip_addr;
	memset(arp_head->arp_dha, 0 , (6 * sizeof(unsigned char)));
	arp_head->arp_dpa = inet_addr(ip_address);
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
	rvalue =-1;
	memset(arp_buffer,0,BUF_SIZE);
	rvalue = recvfrom(arp_fd, arp_buffer, BUF_SIZE, 0, NULL, NULL);
	printf("\n return value %d ",rvalue);
	if( rvalue < 0 )
	{
		perror("recv_from");
		close(arp_fd);
		exit(1);
	}
	memcpy(mac_address,arp_head->arp_sha, (6 * sizeof(unsigned char)));
	printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                mac_address[0],
                mac_address[1],
                mac_address[2],
                mac_address[3],
                mac_address[4],
                mac_address[5]
            );
	close(arp_fd);
	return mac_address;
}
int main (int argc, char **argv){
	char *ipaddress=(char *)malloc(sizeof(char)*10);
	char *device=(char *)malloc(sizeof(char) * 10);
	unsigned char *macad=NULL;
	unsigned char *macaddress= (unsigned char *) malloc (sizeof(unsigned char)*6);
	if (argc < 3 || argc > 4) {
                fprintf(stderr, "error: unrecognized command-line options\n\n");
                print_usage();
                exit(EXIT_FAILURE);
        }
        else if (argc ==3 ) {
		memcpy(device,argv[1],strlen(argv[1]));
		memcpy(ipaddress,argv[2],strlen(argv[2]));
        }
	printf("\n Device %s IPaddress %s",device,ipaddress);
	root = NULL;
	memset(macaddress,0,sizeof(unsigned char)*6);
	
	macad = get_mac_address(ipaddress);
	if(macad==NULL){
                macaddress = get_arp_address(ipaddress,device);
                if(macaddress!=NULL){
                        struct arp_table *arp=(struct arp_table *)malloc(sizeof(struct arp_table));
                        int i;
                        arp->ip_addr = inet_addr(ipaddress);
                        for (i = 0; i < 6; i++) {
                                arp->ether_dhost[i] = macaddress[i];
                        }
                        /*printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                arp->ether_dhost[0],
                                arp->ether_dhost[1],
                                arp->ether_dhost[2],
                                arp->ether_dhost[3],
                                arp->ether_dhost[4],
                                arp->ether_dhost[5]
                        );*/
                  init_list(arp);
                }
        }
	memset(macaddress,0,sizeof(unsigned char)*6);
	macad = get_mac_address(ipaddress);
	memcpy(macaddress,macad,sizeof(unsigned char)*6);
	printf("TARGETlist  MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                macaddress[0],
                macaddress[1],
                macaddress[2],
                macaddress[3],
                macaddress[4],
                macaddress[5]
            );

	return 0;
}
