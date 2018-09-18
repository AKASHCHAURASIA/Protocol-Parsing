#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"C"
#define APP_DISCLAIMER	"T."

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

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_arp {
           uint16_t htype;
           uint16_t ptype;
        uint8_t hsize;
        uint8_t psize;
        uint16_t opcode;
        uint8_t send_mac[6];
        uint32_t send_ip;
        uint8_t tar_mac[6];
        uint32_t tar_ip;
}__attribute__((packed));







void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);


void print_app_banner(void);

void print_app_usage(void);


void print_app_banner(void)
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
void print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_arp *arp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

        printf("Ethernet Header:\n");
	printf("Destination Address:");
	for(int g=0;g<ETHER_ADDR_LEN;g++)
	printf("%X ",ethernet->ether_dhost[g]);
        printf("\nSource Address:");
        for(int g=0;g<ETHER_ADDR_LEN;g++)
        printf("%X ",ethernet->ether_shost[g]);
	printf("\nEthernet Type:\n\n");

        printf("%02x ",ntohs(ethernet->ether_type));
         arp=(struct sniff_arp*)(packet+SIZE_ETHERNET);
	 printf("\nARP HEADER:");
         struct in_addr a,b;

	printf("\n\tHardware type: %02X",ntohs(arp->htype));
	printf("\n\tProtocol type: %02X",ntohs(arp->ptype));
	printf("\n\tHardware size: %02X",(arp->hsize));
	printf("\n\tProtocol size: %02X",(arp->psize));
	printf("\n\tOpcode: %02X",ntohs(arp->opcode));
	printf("\n\tSender MAC address: ");
        for(int i=0;i<6;i++) printf(" %01X",arp->send_mac[i]);
	printf("\n\tSender IP address:");
	a.s_addr = arp->send_ip;
        printf("%s",inet_ntoa(a));
        printf("\n\tTarget MAC address: ");                                             
       	for(int i=0;i<6;i++) printf(" %01X",arp->tar_mac[i]);
        printf("\n\tTarget IP address: ");
																									        b.s_addr = arp->tar_ip;
																										printf("%s",inet_ntoa(b));
                                                                                                  

   

	

	
      
return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
   
	char filter_exp[] = "arp";	
	/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1;			/* number of packets to capture */

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

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

