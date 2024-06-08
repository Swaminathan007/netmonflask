#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <cerrno>
#include <cjson/cJSON.h>
#include <math.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/msg.h>

struct message {
	long mtype;
	char mtext[327680];
};
message msg;

int qid;
int c=0;
char *protocol;
int st = 0;
const struct ip* ipHeader;
char sourceIP[INET_ADDRSTRLEN],destinationIP[INET_ADDRSTRLEN];
uint16_t src_port,dest_port;
struct ether_header *eth_header;
struct ethhdr *ethernet_header;
struct iphdr *ip_header;
unsigned char *payload;
int payload_length;
long int tsec,tusec;
double usec,uusec;
int proto;
double timestamp;
const char *pay_load;
int pacsize;
cJSON *packet_json,*ether_json,*ip_json,*tcp_json,*udp_json,*icmp_json,*trans_json;
struct udphdr *udph;
struct tcphdr *tcph;
char *pacstr;
struct icmphdr *icmph;
char *mac_to_str(const unsigned char *mac) {
    static char mac_str[18];
    sprintf(mac_str, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}
void get_ethernet_header(const struct ether_header *eth_header) {
    ether_json = cJSON_CreateObject();
	cJSON_AddStringToObject(ether_json, "Destination MAC", mac_to_str(eth_header->ether_dhost));
    cJSON_AddStringToObject(ether_json, "Source MAC", mac_to_str(eth_header->ether_shost));
    cJSON_AddNumberToObject(ether_json, "Protocol", ntohs(eth_header->ether_type));
    cJSON_AddItemToObject(packet_json,"Ethernet header",ether_json);
}
void packet_handler(unsigned char *user,const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
		char *dev = (char *)user;
		packet_json = cJSON_CreateObject();
		ip_json = cJSON_CreateObject();
		eth_header = (struct ether_header *)packet;
		ipHeader = reinterpret_cast<const struct ip*>(packet + 14);
        src_port = ntohs(*(uint16_t *)(packet + 14 + ipHeader->ip_hl * 4));
        dest_port = ntohs(*(uint16_t *)(packet + 14 + ipHeader->ip_hl * 4 + 2));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET,&(ipHeader->ip_dst),destinationIP,INET_ADDRSTRLEN);
        ethernet_header = (struct ethhdr *)packet;
        ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
        payload = (unsigned char *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
        payload_length = pkthdr->caplen - sizeof(struct ethhdr) - ip_header->ihl * 4;
        tsec = pkthdr->ts.tv_sec;
        tusec = pkthdr->ts.tv_usec;
        uusec = tusec;
        uusec*=pow(10,-6);
        tsec+=uusec;
        proto = ipHeader->ip_p;
       	timestamp = tsec;
       	pay_load = reinterpret_cast<char*>(payload);
       	char pay[payload_length+1];
       	for(int i=0;i<payload_length;i++){
       		if(!isprint(pay_load[i])){
       			pay[i] = '.';
       		}
       		else{
       			pay[i] = pay_load[i];	
       		}
       	}
       	pay[payload_length] = '\0';
       	cJSON_AddNumberToObject(packet_json,"Timestamp",timestamp);
       	get_ethernet_header(eth_header);
       	cJSON_AddNumberToObject(ip_json,"IP version",ip_header->version);
       	cJSON_AddNumberToObject(ip_json,"IP Header length",ip_header->ihl);
       	cJSON_AddNumberToObject(ip_json,"Type of service",ip_header->tos);
       	cJSON_AddNumberToObject(ip_json,"Identification",ntohs(ip_header->id));
       	cJSON_AddNumberToObject(ip_json,"TTL",ntohs(ip_header->ttl));
       	cJSON_AddNumberToObject(ip_json,"Protocol",ntohs(ip_header->protocol));
       	cJSON_AddNumberToObject(ip_json,"Checksum",ntohs(ip_header->check));
       	cJSON_AddStringToObject(ip_json,"Source IP",sourceIP);
       	cJSON_AddStringToObject(ip_json,"Destination IP",destinationIP);
       	cJSON_AddItemToObject(packet_json,"IP header",ip_json);
       	switch(proto){
       		case 1:
       			trans_json = cJSON_CreateObject();
       			cJSON_AddStringToObject(packet_json,"Protocol",reinterpret_cast<const char*>("ICMP"));
       			icmph = (struct icmphdr *)(packet + ip_header->ihl * 4  + sizeof(struct ethhdr));
       			icmp_json = cJSON_CreateObject();
       			
       			if((unsigned int)(icmph->type) == 11){
       				cJSON_AddStringToObject(icmp_json,"Type",reinterpret_cast<const char*>("TTL Expired"));
				}
				else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY){
					cJSON_AddStringToObject(icmp_json,"Type",reinterpret_cast<const char*>("ICMP Echo Reply"));
				}
				cJSON_AddNumberToObject(icmp_json,"Code",(unsigned int)(icmph->code));
				cJSON_AddNumberToObject(icmp_json,"Checksum",ntohs(icmph->checksum));
				cJSON_AddItemToObject(packet_json,"ICMP Header",icmp_json);
				cJSON_AddNumberToObject(trans_json,"Source port",src_port);
       			cJSON_AddNumberToObject(trans_json,"Destination port",dest_port);
       			cJSON_AddItemToObject(packet_json,"Transport Header",trans_json);
       			break; 
       		case 2:
       			trans_json = cJSON_CreateObject();
       			cJSON_AddStringToObject(packet_json,"Protocol",reinterpret_cast<const char*>("IGMP"));
       			cJSON_AddNumberToObject(trans_json,"Source port",src_port);
       			cJSON_AddNumberToObject(trans_json,"Destination port",dest_port);
       			cJSON_AddItemToObject(packet_json,"Transport Header",trans_json);
       			break;
       		case 6:
       			tcp_json = cJSON_CreateObject();
       			tcph = (struct tcphdr *)(packet + ip_header->ihl * 4  + sizeof(struct ethhdr));
       			cJSON_AddNumberToObject(tcp_json,"Source port",src_port);
       			cJSON_AddNumberToObject(tcp_json,"Destination port",dest_port);
       			cJSON_AddNumberToObject(tcp_json,"Sequence number",ntohl(tcph->seq));
       			cJSON_AddNumberToObject(tcp_json,"Acknowledge Number",ntohl(tcph->ack_seq));
       			cJSON_AddNumberToObject(tcp_json,"Header length",(unsigned int)tcph->doff*4);
       			cJSON_AddNumberToObject(tcp_json,"Urgent Flag",(unsigned int)tcph->urg);
       			cJSON_AddNumberToObject(tcp_json,"Acknowledgement Flag",(unsigned int)tcph->ack);
       			cJSON_AddNumberToObject(tcp_json,"Push Flag",(unsigned int)tcph->psh);
       			cJSON_AddNumberToObject(tcp_json,"Reset Flag",(unsigned int)tcph->rst);
       			cJSON_AddNumberToObject(tcp_json,"Finish Flag",(unsigned int)tcph->fin);
       			cJSON_AddNumberToObject(tcp_json,"Window",ntohs(tcph->window));
       			cJSON_AddNumberToObject(tcp_json,"Checksum",ntohs(tcph->check));
       			cJSON_AddNumberToObject(tcp_json,"Urgent Pointer",tcph->urg_ptr);
       			cJSON_AddStringToObject(packet_json,"Protocol",reinterpret_cast<const char*>("TCP"));
       			cJSON_AddItemToObject(packet_json,"Transport Header",tcp_json);
       			break;
       		case 17:
       			udp_json = cJSON_CreateObject();
       			udph = (struct udphdr *)(packet + ip_header->ihl * 4  + sizeof(struct ethhdr));
       			cJSON_AddNumberToObject(udp_json,"Source port",src_port);
       			cJSON_AddNumberToObject(udp_json,"Destination port",dest_port);
       			cJSON_AddNumberToObject(udp_json,"UDP Length",ntohs(udph->len));
       			cJSON_AddNumberToObject(udp_json,"UDP Checksum",ntohs(udph->check));
       			cJSON_AddStringToObject(packet_json,"Protocol",reinterpret_cast<const char*>("UDP"));
       			cJSON_AddItemToObject(packet_json,"Transport Header",udp_json);
       			break;
       		default:
       			trans_json = cJSON_CreateObject();
       			cJSON_AddStringToObject(packet_json,"Protocol",reinterpret_cast<const char*>("Could not find protocol"));
       			cJSON_AddNumberToObject(trans_json,"Source port",src_port);
       			cJSON_AddNumberToObject(trans_json,"Destination port",dest_port);
       			cJSON_AddItemToObject(packet_json,"Transport Header",trans_json);
       	}
       	cJSON_AddStringToObject(packet_json,"Payload",pay);
       	pacstr = cJSON_Print(packet_json);
       	pacsize = strlen(pacstr);
       	printf("==========================================================================\n");
        printf("%s\n",pacstr);
	   	for(int i=0;i<pacsize;i++){
	    	msg.mtext[i] = pacstr[i];
	    }
	    msg.mtext[pacsize] = '\0';
		printf("Interface         : %s\n",dev);
	    printf("Packet number     : %d\n",++c);
        printf("Packet size       : %d\n",pacsize);
        printf("\n==========================================================================\n");
		
		cJSON_Delete(packet_json);
    	free(pacstr);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];  
    char errbuf[PCAP_ERRBUF_SIZE];  
    pcap_t *handle;  
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Capturing on interface: %s\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}