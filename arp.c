#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
typedef struct{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} __attribute__((packed)) ETH_H;

typedef struct{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hsize;
	uint8_t psize;
	uint16_t opcode;
	uint8_t send_mac[6];
	uint32_t send_ip;
	uint8_t tar_mac[6];
	uint32_t tar_ip;
}__attribute__((packed)) ARP;	


typedef struct {
	ETH_H eth;
	ARP arp;
	} PACKET;

int main(int argc ,char *argv){
	FILE *fp;
	PACKET pkt;
	struct in_addr a,b;
	uint32_t addr;
	fp=fopen("packet.hex","rb");
	if(!fp)
		exit(0);
	fread(&pkt,sizeof(PACKET),1,fp);
	printf("\nEthernet II");
	printf("\n\tDestination:");	
	for(int i=0;i<6;i++) printf(" %01X",pkt.eth.dst[i]);
	printf("\n\tSource:");
	for(int i=0;i<6;i++) printf(" %01X",pkt.eth.src[i]);
	printf("\n\tType:%02X\n",ntohs(pkt.eth.type));
	printf("\nAddress Resolution Protocol");
	printf("\n\tHardware type: %02X",ntohs(pkt.arp.htype));
	printf("\n\tProtocol type: %02X",ntohs(pkt.arp.ptype));
	printf("\n\tHardware size: %02X",(pkt.arp.hsize));
	printf("\n\tProtocol size: %02X",(pkt.arp.psize));
	printf("\n\tOpcode: %02X",ntohs(pkt.arp.opcode));
	printf("\n\tSender MAC address: ");
	for(int i=0;i<6;i++) printf(" %01X",pkt.arp.send_mac[i]);
	printf("\n\tSender IP address: ");
	a.s_addr = pkt.arp.send_ip;
	printf("%s",inet_ntoa(a));
	printf("\n\tTarget MAC address: ");
	for(int i=0;i<6;i++) printf(" %01X",pkt.arp.tar_mac[i]);
	printf("\n\tTarget IP address: ");
	b.s_addr = pkt.arp.tar_ip;
	printf("%s",inet_ntoa(b));
	addr = ntohl(pkt.arp.tar_ip);
	printf("%d\n",addr);
	printf("IP1 : %d ", (addr >> 4) & 0xFF);
	printf("IP2 : %d ", (addr >> 8) & 0xFF);
	printf("IP3 : %d ", (addr >> 16) & 0xFF);
	printf("IP4 : %d ", (addr >> 24) & 0xFF);
	printf("\n");
}
