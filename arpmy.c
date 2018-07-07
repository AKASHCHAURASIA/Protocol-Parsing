#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct {
        uint16_t ether;
        uint16_t proto;
        uint8_t et_size;
        uint8_t pro_size;
        uint16_t op;
        uint8_t smac[6];
        uint8_t sip[4];
	uint8_t tmac[6];
	uint8_t tip[4];
	
} ARP_H;

int main(int argc, char* argv){
	FILE *fp;
	ARP_H eth;

	fp = fopen("packet.hex","rb");
        fseek(fp,14,SEEK_SET);
	if(!fp) exit(0);
	fread(&eth,sizeof( ARP_H),1,fp);
       
	printf("\nHardware-Type: ");
        printf("%02X ",ntohs(eth.ether));
        printf("\nProctocol-Type: ");
        printf("%02X ",eth.proto);
        printf("\nHardware-Size: ");
        printf("%01X ",eth.et_size);
        printf("\nProctocol-size: ");
        printf("%01X ",eth.pro_size);
        printf("\nOPCODE: ");
        printf("%02X ",ntohs(eth.op));

        printf("\nSENDER-MAC: ");
	for(int i=0;i<6;i++) printf("%01X:",eth.smac[i]);
           printf("\nSENDER-IP: ");
	for(int i=0;i<4;i++) printf("%01d .",eth.sip[i]);
         printf("\nTARGET-MAC: ");
	for(int i=0;i<6;i++) printf("%01X:",eth.tmac[i]);
           printf("\nTARGET-IP: ");
	for(int i=0;i<4;i++) printf("%01d .",eth.tip[i]);

	
	
}
