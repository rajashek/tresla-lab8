#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
 #include <net/route.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

u_short ip_checksum(u_short *ptr,int nbytes) {
    // Create Checksum of IP header (Modified version)
    // original: http://www.binarytides.com/raw-udp-sockets-c-linux/
    //

    
    
    long sum;
    u_short oddbyte = 0;
    short answer = 0;
    
    sum=0;
    while(nbytes>1) {
        
        printf("%.4x\n", ntohs(*(ptr)));
        
        sum+=ntohs(*ptr++);
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=htons((u_short)~sum);
    
    return answer;
}
unsigned int add_to_table(char *dest, char *gw){
  int ret;
  int sock;
  struct rtentry rtentry;
  struct sockaddr_in sin_dest, sin_mask, sin_gate;

  memset (&rtentry, 0, sizeof (struct rtentry));

  /* Make destination. */
  memset (&sin_dest, 0, sizeof (struct sockaddr_in));
  sin_dest.sin_family = AF_INET;
  sin_dest.sin_addr.s_addr = inet_addr(dest);
  sin_dest.sin_port = 0;
  /* Make gateway. */
  memset (&sin_gate, 0, sizeof (struct sockaddr_in));
  sin_gate.sin_family = AF_INET;
  sin_gate.sin_addr.s_addr = inet_addr(gw);
  sin_gate.sin_port = 0;
  
  memset (&sin_mask, 0, sizeof (struct sockaddr_in));
  sin_mask.sin_family = AF_INET;
  sin_mask.sin_addr.s_addr=0x00FFFFFF;
  sin_mask.sin_port = 0;
  /* Set destination address, mask and gateway.*/
  memcpy (&rtentry.rt_dst, &sin_dest, sizeof (struct sockaddr_in));
  memcpy (&rtentry.rt_gateway, &sin_gate, sizeof (struct sockaddr_in));
  memcpy (&rtentry.rt_genmask, &sin_mask, sizeof (struct sockaddr_in));

  /* Routing entry flag set. */
  rtentry.rt_flags |= RTF_HOST;

  rtentry.rt_flags |= RTF_GATEWAY;

  rtentry.rt_flags |= RTF_UP;



  /* For tagging route. */
  /* rtentry.rt_flags |= RTF_DYNAMIC; */

  /* Open socket for ioctl. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      printf("can't make socket\n");
      return -1;
    }

  /* Send message by ioctl(). */
  ret = ioctl (sock, SIOCADDRT, &rtentry);
  printf("\n rvalue %s ",strerror(errno));  
  if (ret < 0)
  {
      switch (errno) 
	{
	case EEXIST:
	  close (sock);
	printf("%s",strerror(errno));  
	break;
	case ENETUNREACH:
	  close (sock);
	printf("%s",strerror(errno));  
	  break;
	case EPERM:
	  close (sock);
	printf("%s",strerror(errno));  
	  break;
	}

      close (sock);
      return 1;
  }
  close (sock);

  return ret;
}



/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	/* declare pointers to packet headers */
	struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	struct ifreq ifr;
	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	char ipnode3[] = "10.1.2.3";
	char ipnode4[] = "10.1.2.4";
	if(strcmp(inet_ntoa(ip->ip_dst),ipnode3)==0){
		ethernet->ether_shost[0]=0x00;
        	ethernet->ether_shost[1]=0x15;
        	ethernet->ether_shost[2]=0x17;
        	ethernet->ether_shost[3]=0x5d;
        	ethernet->ether_shost[4]=0x27;
        	ethernet->ether_shost[5]=0xe8;

        	ethernet->ether_dhost[0]=0x00;
        	ethernet->ether_dhost[1]=0x15;
        	ethernet->ether_dhost[2]=0x17;
        	ethernet->ether_dhost[3]=0x5d;
       		ethernet->ether_dhost[4]=0x29;
        	ethernet->ether_dhost[5]=0x88;
		const char *IP_gw = "10.1.2.1";
		const char *IP_dst = "10.1.2.3";
		strcpy(ifr.ifr_name,"eth0");
		printf("The destination IP is node 3\n");
	}

	else if(strcmp(inet_ntoa(ip->ip_dst),ipnode4)==0){
                ethernet->ether_shost[0]=0x00;
                ethernet->ether_shost[1]=0x15;
                ethernet->ether_shost[2]=0x17;
                ethernet->ether_shost[3]=0x5d;
                ethernet->ether_shost[4]=0x27;
                ethernet->ether_shost[5]=0xe8;

                ethernet->ether_dhost[0]=0x00;
                ethernet->ether_dhost[1]=0x15;
                ethernet->ether_dhost[2]=0x17;
                ethernet->ether_dhost[3]=0x5d;
                ethernet->ether_dhost[4]=0x16;
                ethernet->ether_dhost[5]=0xb4;
		strcpy(ifr.ifr_name,"eth0");
		printf("The destination IP is node 4\n");
        }

		
	else {	
	    	ethernet->ether_shost[0]=0x00;
    		ethernet->ether_shost[1]=0x15;
    		ethernet->ether_shost[2]=0x17;
    		ethernet->ether_shost[3]=0x5d;
	    	ethernet->ether_shost[4]=0x27;
	    	ethernet->ether_shost[5]=0xe9;

		ethernet->ether_dhost[0]=0x00;
		ethernet->ether_dhost[1]=0x15;
		ethernet->ether_dhost[2]=0x17;
		ethernet->ether_dhost[3]=0x5d;
		ethernet->ether_dhost[4]=0x29;
		ethernet->ether_dhost[5]=0xe5;
		strcpy(ifr.ifr_name,"eth2");
		printf("The destination IP is a remote subnet\n");
	}

	printf("         Modified Destination Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ethernet->ether_dhost[0],
                                                                        (unsigned char)ethernet->ether_dhost[1],
                                                                        (unsigned char)ethernet->ether_dhost[2],
                                                                        (unsigned char)ethernet->ether_dhost[3],
                                                                        (unsigned char)ethernet->ether_dhost[4],
                                                                        (unsigned char)ethernet->ether_dhost[5]);
	printf("         Modified Source Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ethernet->ether_shost[0],
                                                                        (unsigned char)ethernet->ether_shost[1],
                                                                        (unsigned char)ethernet->ether_shost[2],
                                                                        (unsigned char)ethernet->ether_shost[3],
                                                                        (unsigned char)ethernet->ether_shost[4],
                                                                        (unsigned char)ethernet->ether_shost[5]);
    	// Decrease TTL
    	ip->ip_ttl = ip->ip_ttl-1;
    	ip->ip_sum = 0;
    	ip->ip_sum = ip_checksum((u_short *) (packet + SIZE_ETHERNET), sizeof(struct sniff_ip));

    
    
	int fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_802_3));
	if (fd==-1) {
    		printf("%s",strerror(errno));
	}
	//struct ifreq ifr;
	//strcpy(ifr.ifr_name,"eth2");
	if (ioctl(fd,SIOCGIFINDEX,&ifr)==-1) {
    		printf("%s",strerror(errno));
	}
	int ifindex=ifr.ifr_ifindex;
	struct sockaddr_ll addr={0};
	addr.sll_family=PF_PACKET;
	addr.sll_ifindex=ifindex;
	addr.sll_halen=ETHER_ADDR_LEN;
	addr.sll_protocol=htons(ETH_P_802_3);
	addr.sll_hatype = 0;
	addr.sll_pkttype = 0;
	memcpy(addr.sll_addr, ethernet->ether_shost, ETHER_ADDR_LEN);
    
    print_payload(packet, header->caplen);
    
	if (bind(fd,(struct sockaddr *)&addr, sizeof(addr))==0){
		printf("Bind succesful\n");
	}
	int n;
	if ( n=send(fd,packet, header->len, 0) < 0) {
    		printf("%s",strerror(errno));
	}
	printf(" 	The packets sent size %d\n", header->len);
    printf("%d\n", sizeof(struct sniff_ip));
	return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	unsigned int r_value ;
        char ipnode3[] = "10.1.2.3";
        char ipnode4[] = "10.1.2.4";
        r_value = add_to_table(ipnode3,"10.1.2.1");
        //usleep(10);
        r_value = add_to_table(ipnode4,"10.1.2.1");
       // usleep(10);
        r_value = add_to_table("10.10.1.1","10.10.1.2");	
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

