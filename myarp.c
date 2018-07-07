#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} ETH_H;

int main(int argc, char* argv){
	FILE *fp;
	ETH_H eth;

	fp = fopen("packet.hex","rb");
	if(!fp) exit(0);
	fread(&eth,sizeof( ETH_H),1,fp);
	printf("\nDST: ");
	for(int i=0;i<6;i++) printf("%01X ",eth.dst[i]);
	printf("\nSRC: ");
	for(int i=0;i<6;i++) printf("%01X ",eth.src[i]);
	printf("\nTYPE: %02X\n",ntohs(eth.type)); 
}
