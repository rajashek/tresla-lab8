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
#include<pthread.h>
#include <netinet/ip_icmp.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define SIZE_ICMP 8
/*icmp header creation*/
struct icmpheader
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t  checksum;
    u_int32_t rest;	
};


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

int raw_fd2;

void
got_packet2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload2(const u_char *payload, int len);

void
print_hex_ascii_line2(const u_char *payload, int len, int offset);

void
print_app_usage2(void);


/*
 * print help text
 */
void
print_app_usage2(void)
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
print_hex_ascii_line2(const u_char *payload, int len, int offset)
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
print_payload2(const u_char *payload, int len)
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
        print_hex_ascii_line2(ch, len, offset);
        return;
    }
    
    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line2(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line2(ch, len_rem, offset);
            break;
        }
    }
    
    return;
}

u_short ip_checksum2(u_short *ptr,int nbytes) {
    // Create Checksum of IP header (Modified version)
    // original: http://www.binarytides.com/raw-udp-sockets-c-linux/
    //
    
    long sum;
    u_short oddbyte = 0;
    short answer = 0;
    
    sum=0;
    while(nbytes>1) {
        
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


unsigned short calcsum(unsigned short *buffer, int length)
{
    unsigned long sum;
    
    // initialize sum to zero and loop until length (in words) is 0
    for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words
        sum += *buffer++;	// add 1 word of buffer to sum and proceed to the next
    
    // we may have an extra byte
    if (length==1)
        sum += (char)*buffer;
    
    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16
    sum += (sum >> 16);		     // add carry
    return ~sum;
}

/*
 * dissect/print packet
 */
void
got_packet2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("IN GOT PACKET2\n");
    static int count = 1;                   /* packet counter */
    /* declare pointers to packet headers */
    struct sniff_ethernet *ethernet2;  /* The ethernet header [1] */
    struct sniff_ip *ip2;              /* The IP header */
    const struct sniff_tcp *tcp2;            /* The TCP header */
    const char *payload;                    /* Packet payload */
    
    int size_ip;
    int size_tcp;
    int size_payload;
    
    
    printf("\nPacket number %d:\n", count);
    count++;
    
    /* define ethernet header */
    ethernet2 = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip2 = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip2)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    struct ifreq ifr2;
    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip2->ip_src));
    printf("         To: %s\n", inet_ntoa(ip2->ip_dst));
    char ipnode3[] = "10.1.2.3";
    char ipnode4[] = "10.1.2.4";
   // char srcnode[] = "10.10.1.2";
    // 00:04:23:a6:55:5c
    if(strcmp(inet_ntoa(ip2->ip_dst),ipnode3)==0 || strcmp(inet_ntoa(ip2->ip_dst),ipnode4)==0) {
        ethernet2->ether_shost[0]=0x00;
        ethernet2->ether_shost[1]=0x04;
        ethernet2->ether_shost[2]=0x23;
        ethernet2->ether_shost[3]=0xa6;
        ethernet2->ether_shost[4]=0x55;
        ethernet2->ether_shost[5]=0x5c;
        // 00:04:23:ad:d8:55
        //00:04:23:b5:d5:ba
        //given only node4 as of now
        ethernet2->ether_dhost[0]=0x00;
        ethernet2->ether_dhost[1]=0x04;
        ethernet2->ether_dhost[2]=0x23;
        ethernet2->ether_dhost[3]=0xb5;
        ethernet2->ether_dhost[4]=0xd5;
        ethernet2->ether_dhost[5]=0xba;
        strcpy(ifr2.ifr_name,"eth3");
        printf("If of got_packet2\n");
    }
    else {
        ethernet2->ether_shost[0]=0x00;
        ethernet2->ether_shost[1]=0x0e;
        ethernet2->ether_shost[2]=0x0c;
        ethernet2->ether_shost[3]=0x09;
        ethernet2->ether_shost[4]=0x80;
        ethernet2->ether_shost[5]=0x9f;
        // 00:04:23:ad:d8:55
        ethernet2->ether_dhost[0]=0x00;
        ethernet2->ether_dhost[1]=0x04;
        ethernet2->ether_dhost[2]=0x23;
        ethernet2->ether_dhost[3]=0xad;
        ethernet2->ether_dhost[4]=0xd8;
        ethernet2->ether_dhost[5]=0x55;
        strcpy(ifr2.ifr_name,"eth0");
        printf("else of got_packet2\n");
    }
    // Decrease TTL
    ip2->ip_ttl = ip2->ip_ttl-1;
    printf("The ttl value is %d G_P2\n",ip2->ip_ttl);
    int ret_val;
    struct icmpheader *icmp = (struct icmpheader *)(packet + SIZE_ETHERNET + size_ip);
    char* data = (char*)(icmp)+SIZE_ICMP;
    memcpy(data,ip2,(size_ip+8));
    if(ip2->ip_ttl ==0) {
	printf("I am in TRACEROUTE G_P2\n");
        ip2->ip_dst = ip2->ip_src;
	ip2->ip_p = 1;
	ip2->ip_ttl =0;
	ip2-> ip_tos = 0xc0;
	icmp->rest=0x00;
	inet_aton("10.1.2.1",&(ip2->ip_src));
	icmp->type = ICMP_TIME_EXCEEDED;
        icmp->code = ICMP_NET_UNREACH;
	icmp->checksum =0;
        icmp->checksum = ip_checksum2((u_short *) (packet + SIZE_ETHERNET+size_ip), header->len-(SIZE_ETHERNET+size_ip));

//	header->len = SIZE_ICMP + SIZE_ETHERNET + size_ip;
	ethernet2->ether_shost[0]=0x00;
        ethernet2->ether_shost[1]=0x04;
        ethernet2->ether_shost[2]=0x23;
        ethernet2->ether_shost[3]=0xa6;
        ethernet2->ether_shost[4]=0x57;
        ethernet2->ether_shost[5]=0x99;
        // 00:04:23:a6:57:79
        ethernet2->ether_dhost[0]=0x00;
        ethernet2->ether_dhost[1]=0x04;
        ethernet2->ether_dhost[2]=0x23;
        ethernet2->ether_dhost[3]=0xa6;
        ethernet2->ether_dhost[4]=0x57;
        ethernet2->ether_dhost[5]=0x79;
	
	strcpy(ifr2.ifr_name,"eth4");
        }

    ip2->ip_sum = 0;
    ip2->ip_sum = ip_checksum2((u_short *) (packet + SIZE_ETHERNET), sizeof(struct sniff_ip));
    //strcpy(ifr.ifr_name,"eth2");
    if (ioctl(raw_fd2,SIOCGIFINDEX,&ifr2)==-1) {
        printf("%s",strerror(errno));
    }
    int ifindex2=ifr2.ifr_ifindex;
    struct sockaddr_ll addr2={0};
    addr2.sll_family=PF_PACKET;
    addr2.sll_ifindex=ifindex2;
    addr2.sll_halen=ETHER_ADDR_LEN;
    addr2.sll_protocol=htons(ETH_P_802_3);
    addr2.sll_hatype = 0;
    addr2.sll_pkttype = 0;
    memcpy(addr2.sll_addr, ethernet2->ether_shost, ETHER_ADDR_LEN);
    
    //print_payload2(packet, header->caplen);
    
    if (bind(raw_fd2,(struct sockaddr *)&addr2, sizeof(addr2))==0){
        printf("Bind succesful\n");
    }
    int n;
    if ( n=send(raw_fd2,packet,header->len, 0) < 0) {
        printf("%s",strerror(errno));
    }
    printf(" 	The packets sent size %d\n", header->len);
    printf("%d\n", sizeof(struct sniff_ip));
    return;
}

void* thread_interface2()
{
    
    
    char errbuf2[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle2;				/* packet capture handle */
    
    char filter_exp2[] = "ip and ether dst 00:04:23:a6:57:99";		/* filter expression [3] */
    //  char filter_exp2[] = "ip";
    struct bpf_program fp2;			/* compiled filter program (expression) */
    bpf_u_int32 mask2;			/* subnet mask */
    bpf_u_int32 net2;			/* ip */
    int num_packets2 = 10000;			/* number of packets to capture */
    char dev2[5] = "eth4";
    printf("IN THREAD_INTERFACE2\n");
    
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev2, &net2, &mask2, errbuf2) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev2, errbuf2);
        net2 = 0;
        mask2 = 0;
    }
    
    /* print capture info */
    
    printf("CHECK Device: %s\n", dev2);
    printf("Number of packets: %d\n", num_packets2);
    printf("second Filter expression: %s\n", filter_exp2);
    
    /* open capture device */
    handle2 = pcap_open_live(dev2, SNAP_LEN, 1, 1000, errbuf2);
    if (handle2 == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev2, errbuf2);
        exit(EXIT_FAILURE);
    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle2) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev2);
        exit(EXIT_FAILURE);
    }
    printf("Check1\n");
    
    /* compile the filter expression */
    if (pcap_compile(handle2, &fp2, filter_exp2, 0, net2) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp2, pcap_geterr(handle2));
        exit(EXIT_FAILURE);
    }
    printf("Check2\n");
    /* apply the compiled filter */
    if (pcap_setfilter(handle2, &fp2) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp2, pcap_geterr(handle2));
        exit(EXIT_FAILURE);
    }
    printf("Check3\n");
    raw_fd2=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_802_3));
    if (raw_fd2==-1) {
        printf("%s Socket error\n",strerror(errno));
    }
    pcap_loop(handle2, num_packets2, got_packet2, NULL);
    close(raw_fd2);
    /* cleanup */
    printf("Check4\n");
    pcap_freecode(&fp2);
    pcap_close(handle2);
    
    printf("\nCapture complete.\n");
    
    return 0;
}


//--------------------------------------
int raw_fd;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);


void
print_app_usage(void);


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


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("IN GOT_PACKET\n");
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
    /*
     ethernet->ether_shost[0]=0x00;
     ethernet->ether_shost[1]=0x0e;
     ethernet->ether_shost[2]=0x0c;
     ethernet->ether_shost[3]=0x09;
     ethernet->ether_shost[4]=0x80;
     ethernet->ether_shost[5]=0x9f;
     
     ethernet->ether_dhost[0]=0x00;
     ethernet->ether_dhost[1]=0x04;
     ethernet->ether_dhost[2]=0x23;
     ethernet->ether_dhost[3]=0xa6;
     ethernet->ether_dhost[4]=0x55;
     ethernet->ether_dhost[5]=0x5c;
     strcpy(ifr.ifr_name,"eth3");
     */
    if(strcmp(inet_ntoa(ip->ip_dst),ipnode3)==0 || strcmp(inet_ntoa(ip->ip_dst),ipnode4)==0) {
        ethernet->ether_shost[0]=0x00;
        ethernet->ether_shost[1]=0x04;
        ethernet->ether_shost[2]=0x23;
        ethernet->ether_shost[3]=0xa6;
        ethernet->ether_shost[4]=0x55;
        ethernet->ether_shost[5]=0x5c;
        
        ethernet->ether_dhost[0]=0x00;
        ethernet->ether_dhost[1]=0x04;
        ethernet->ether_dhost[2]=0x23;
        ethernet->ether_dhost[3]=0xb5;
        ethernet->ether_dhost[4]=0xd5;
        ethernet->ether_dhost[5]=0xba;
        strcpy(ifr.ifr_name,"eth3");
        printf("From node1 to node3/4 in eth2\n");
    }
    else {
        ethernet->ether_shost[0]=0x00;
        ethernet->ether_shost[1]=0x0e;
        ethernet->ether_shost[2]=0x0c;
        ethernet->ether_shost[3]=0x09;
        ethernet->ether_shost[4]=0x80;
        ethernet->ether_shost[5]=0x9f;
        // 00:04:23:ad:d8:55
        // 00:04:23:ad:d8:55
        ethernet->ether_dhost[0]=0x00;
        ethernet->ether_dhost[1]=0x04;
        ethernet->ether_dhost[2]=0x23;
        ethernet->ether_dhost[3]=0xad;
        ethernet->ether_dhost[4]=0xd8;
        ethernet->ether_dhost[5]=0x55;
        printf("I AM IN ELSE of GOT_PACKET\n");
        strcpy(ifr.ifr_name,"eth0");
    }
    
    
    /*printf("         Modified Destination Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ethernet->ether_dhost[0],
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
     (unsigned char)ethernet->ether_shost[5]);*/
    // Decrease TTL
    ip->ip_ttl = ip->ip_ttl-1;
    printf("The value of ttl is %c\n",ip->ip_ttl);
    struct icmpheader *icmp2 = (struct icmpheader *)(size_ip + SIZE_ETHERNET);
    if(ip->ip_ttl ==0) {
        printf("I am in TRACEROUTE\n");
        ip-> ip_dst = ip->ip_src;
       // ip2->ip_src = inet_addr("10.10.1.2");
        inet_aton("10.10.1.2",&(ip->ip_src));
        icmp2 -> type = ICMP_TIME_EXCEEDED;
        icmp2 -> code = ICMP_NET_UNREACH;
        icmp2->checksum =0;
        icmp2->checksum = calcsum((unsigned short*)icmp2, sizeof(struct icmpheader));
        }

    ip->ip_sum = 0;
    ip->ip_sum = ip_checksum((u_short *) (packet + SIZE_ETHERNET), sizeof(struct sniff_ip));
    
    
    
    //struct ifreq ifr;
    //strcpy(ifr.ifr_name,"eth2");
    if (ioctl(raw_fd,SIOCGIFINDEX,&ifr)==-1) {
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
    
    //print_payload(packet, header->caplen);
    
    if (bind(raw_fd,(struct sockaddr *)&addr, sizeof(addr))==0){
        printf("Bind succesful\n");
    }
    else
        printf("Bind unsuccessful %s\n",strerror(errno));
    int n;
    if ( n=send(raw_fd,packet, header->len, 0) < 0) {
        printf("There is a send error %s\n",strerror(errno));
    }
    printf(" 	The packets sent size %d\n", header->len);
    printf("%d\n", sizeof(struct sniff_ip));
    return;
}

void* thread_interface()
{
    
    //char *dev = NULL;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    
    char filter_exp[] = "ip and ether dst 00:04:23:a6:cc:2c";		/* filter expression [3] */
    //char filter_exp[] = "ip";
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = 10000;			/* number of packets to capture */
    
    
    char dev[5] = "eth0";
    printf("IN THREAD_INTERFACE\n");
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
    /*unsigned int r_value ;
     char ipnode3[] = "10.1.2.3";
     char ipnode4[] = "10.1.2.4";
     r_value = add_to_table(ipnode3,"10.1.2.1");
     r_value = add_to_table(ipnode4,"10.1.2.1");
     r_value = add_to_table("10.10.1.1","10.10.1.2");*/
    /* now we can set our callback function */
    raw_fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_802_3));
    if (raw_fd==-1) {
        printf("%s",strerror(errno));
    }
    pcap_loop(handle, num_packets, got_packet, NULL);
    close(raw_fd);
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    printf("\nCapture complete.\n");
    
    return 0;
}

int main() {
    pthread_t thread1, thread2;
    pthread_create(&thread1,0,thread_interface,NULL);
    pthread_create(&thread2,0,thread_interface2,NULL);
    
    pthread_join(thread1,0);
    pthread_join(thread2,0);
    
    printf("Both threads have left.. Exiting\n");
    return 0;
}
