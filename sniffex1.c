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
}__attribute__((packed));


typedef struct dns_rr {
	    
	uint16_t type;
        uint16_t class;
	uint32_t ttl; 
	uint16_t data_len;

}__attribute__((packed));

typedef struct dns_rrc {
	    
	char * name;
	uint16_t type;
        uint16_t cls;
	const char * rr_name;
	uint16_t ttl;
	uint16_t rdlength;
	uint16_t data_len;
	char * data;
	struct dns_rr * next;
};
typedef struct question {

	  char name[255];


}__attribute__((packed));

typedef struct ansrs {

	  char name[255];


}__attribute__((packed));
typedef struct rr_name{
        
char rr_na[255];

}__attribute__((packed));


typedef struct rr_addr{
        
uint32_t  addr;

}__attribute__((packed));

typedef struct rr_addr6 {
        
uint32_t addr[4];

}__attribute__((packed));






struct sniff_dns {
        u_short  t_id;                
        u_short  flags;                
        u_short q;                
        u_short a;                 
        u_short at;
       	u_short add;                   
       struct question query;                         

       u_short nscount;
       struct dns_rr * name_servers;
       u_short arcount;
       struct dns_rr * additional;
      
}__attribute__((packed));


typedef struct qc {
	           
	        
	      uint16_t type;
	      uint16_t class;    
	      struct  dns_rr answers;

}__attribute__((packed));







void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);








void anss(const struct sniff_dns *dns,const struct ansrs *name,const struct dns_rr *answers,const struct rr_addr *adr,const struct  rr_addr6 *adr6,const struct rr_name *adr_name,int i,uint16_t size_ip,const u_char *packet) 
{
printf("\n\tAnswers:");
static int j=0;
static char *cname="op";
static c_name=0;
static data_l=0;
int l;
name = (struct ansrs*)(packet + SIZE_ETHERNET+20+9+12+i+4+j);
for(l=0;name->name[l]!='\0';l++);

if(l>2)
{
	printf("\n\ Name: %s",name->name);
	l-1;
}
else if(c_name==0){
dns = (struct sniff_dns*)(packet + SIZE_ETHERNET+20+8);

	printf("\n\ Name: %s",dns->query.name);
}
else if(c_name) {

	printf("\n\ Name: %s",cname);
}

answers = (struct dns_rr*)(packet + SIZE_ETHERNET+20+9+12+i+l+4+j);
printf("\n\ type: %02X",ntohs(answers->type));
printf("\n\ Class: %02X",ntohs(answers->class));
printf("\n\ TTL: %ld",ntohl(answers->ttl));
int k;
printf("\n\ DATA Len: %02X",ntohs(answers->data_len));
k=ntohs(answers->data_len);
if(ntohs(answers->type)==01)
{ 
 adr = (struct rr_addr*)(packet + SIZE_ETHERNET+20+9+12+i+4+l+10+j);
 struct in_addr a;
 a.s_addr=adr->addr;
printf("\n\ Address:%s",inet_ntoa(a)); 
j=j+12+k;
c_name=0;
}


if(ntohs(answers->type)==28)
{ 
 adr6 = (struct rr_addr6*)(packet + SIZE_ETHERNET+20+9+12+i+4+l+10+j);
struct in6_addr a;
struct sockaddr_in6 sa;
char str[INET6_ADDRSTRLEN];
inet_ntop(AF_INET6, &(adr6->addr), str, INET6_ADDRSTRLEN);

printf("\n\ Address:%s\n", str); 
j=j+12+k;
c_name=0;
}



if(ntohs(answers->type)==05)
{ 
 adr_name = (struct rr_name*)(packet + SIZE_ETHERNET+20+9+12+i+4+10+l+j);
  printf("\n\ CNAME:%s",adr_name->rr_na); 
c_name++;
cname=adr_name->rr_na;

j=j+12+k;

}
printf("\nvalue:%d",j);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;  
	
	const struct sniff_ethernet *ethernet;  
	const struct sniff_arp *arp;
        const struct sniff_dns  *dns;   	
        const struct  qc  *qc;   	
        const struct  rr_addr  *adr;   	
        const struct  rr_addr6  *adr6;   	
	const char *payload;                    
        const struct  dns_rr  *ans;   	

        const struct  ansrs  *na;   	
        const struct  rr_name  *adr_name;   	
	int size_ip;
	int i;
	int size_tcp;
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
      if(ntohs(ethernet->ether_type)==806)
      {
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
                                                                                                  

      }
   

 dns = (struct sniff_dns*)(packet + SIZE_ETHERNET+20+8);
printf("\n\tTransaction Id: %02X",ntohs(dns->t_id));


printf("\n\tflags: %02X",ntohs(dns->flags));

printf("\n\tQuestions: %X",ntohs(dns->q));
   
printf("\n\tAnswers RRs: %X",ntohs(dns->a));

printf("\n\tAuthority RRs: %02X",ntohs(dns->at));        
printf("\n\tAdditional RRs: %02X",ntohs(dns->add));
printf("\n\tquerys:");


printf("\n\tname: %s",dns->query.name);
for(i=0;dns->query.name[i]!='\0';i++);

qc = (struct qc*)(packet + SIZE_ETHERNET+20+9+12+i);
printf("\n\ type: %02X",ntohs(qc->type));
printf("\n\ class: %02X",ntohs(qc->class));

//static int j=0;
int p=ntohs(dns->a);

while(p)
{       anss(dns,na,ans,adr,adr6,adr_name,i,20,packet);
	p--;
}

      
return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
   
	char filter_exp[] = "port 53 and ("
	"(udp and (not udp[10] & 128 = 0)) or"
	"(tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0))"
")";	
	/* filter expression [3] */
	struct bpf_program fp;		
	bpf_u_int32 mask;			
	bpf_u_int32 net;	
	int num_packets = 1;		


	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

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

