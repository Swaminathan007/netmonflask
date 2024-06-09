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
#include <errno.h>
#include <math.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

// Define the maximum payload size
#define MAX_PAYLOAD_SIZE 32768

struct ether_header *eth_header;
struct ip *ipHeader;
char sourceIP[INET_ADDRSTRLEN], destinationIP[INET_ADDRSTRLEN];
uint16_t src_port, dest_port;
unsigned char *payload;
int payload_length;
double timestamp;
struct tcphdr *tcph;
struct udphdr *udph;
struct icmphdr *icmph;
cJSON *packet_json, *ether_json, *ip_json, *tcp_json, *udp_json, *icmp_json, *trans_json;
char *pacstr;

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
    cJSON_AddItemToObject(packet_json, "Ethernet header", ether_json);
}

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    char *dev = (char *)user;
    packet_json = cJSON_CreateObject();
    ip_json = cJSON_CreateObject();
    eth_header = (struct ether_header *)packet;
    ipHeader = (struct ip*)(packet + 14);
    src_port = ntohs(*(uint16_t *)(packet + 14 + ipHeader->ip_hl * 4));
    dest_port = ntohs(*(uint16_t *)(packet + 14 + ipHeader->ip_hl * 4 + 2));
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destinationIP, INET_ADDRSTRLEN);
    payload = (unsigned char *)(packet + 14 + ipHeader->ip_hl * 4);
    payload_length = pkthdr->caplen - 14 - ipHeader->ip_hl * 4;
    timestamp = pkthdr->ts.tv_sec + (pkthdr->ts.tv_usec / 1000000.0);
    char pay[MAX_PAYLOAD_SIZE + 1];
    for (int i = 0; i < payload_length && i < MAX_PAYLOAD_SIZE; i++) {
        pay[i] = isprint(payload[i]) ? payload[i] : '.';
    }
    pay[payload_length] = '\0';
    cJSON_AddNumberToObject(packet_json, "Timestamp", timestamp);
    get_ethernet_header(eth_header);
    cJSON_AddNumberToObject(ip_json, "IP version", ipHeader->ip_v);
    cJSON_AddNumberToObject(ip_json, "IP Header length", ipHeader->ip_hl);
    cJSON_AddNumberToObject(ip_json, "Type of service", ipHeader->ip_tos);
    cJSON_AddNumberToObject(ip_json, "Identification", ntohs(ipHeader->ip_id));
    cJSON_AddNumberToObject(ip_json, "TTL", ipHeader->ip_ttl);
    cJSON_AddNumberToObject(ip_json, "Protocol", ipHeader->ip_p);
    cJSON_AddNumberToObject(ip_json, "Checksum", ntohs(ipHeader->ip_sum));
    cJSON_AddStringToObject(ip_json, "Source IP", sourceIP);
    cJSON_AddStringToObject(ip_json, "Destination IP", destinationIP);
    cJSON_AddItemToObject(packet_json, "IP header", ip_json);
    
    switch (ipHeader->ip_p) {
        case IPPROTO_ICMP:
            trans_json = cJSON_CreateObject();
            cJSON_AddStringToObject(packet_json, "Protocol", "ICMP");
            icmph = (struct icmphdr *)(packet + 14 + ipHeader->ip_hl * 4);
            icmp_json = cJSON_CreateObject();
            cJSON_AddNumberToObject(icmp_json, "Type", icmph->type);
            cJSON_AddNumberToObject(icmp_json, "Code", icmph->code);
            cJSON_AddNumberToObject(icmp_json, "Checksum", ntohs(icmph->checksum));
            cJSON_AddItemToObject(packet_json, "ICMP Header", icmp_json);
            cJSON_AddNumberToObject(trans_json, "Source port", src_port);
            cJSON_AddNumberToObject(trans_json, "Destination port", dest_port);
            cJSON_AddItemToObject(packet_json, "Transport Header", trans_json);
            break;
        case IPPROTO_TCP:
            tcp_json = cJSON_CreateObject();
            tcph = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
            cJSON_AddNumberToObject(tcp_json, "Source port", src_port);
            cJSON_AddNumberToObject(tcp_json, "Destination port", dest_port);
            cJSON_AddNumberToObject(tcp_json, "Sequence number", ntohl(tcph->seq));
            cJSON_AddNumberToObject(tcp_json, "Acknowledge Number", ntohl(tcph->ack_seq));
            cJSON_AddNumberToObject(tcp_json, "Header length", tcph->doff * 4);
            cJSON_AddNumberToObject(tcp_json, "Flags", tcph->th_flags);
            cJSON_AddNumberToObject(tcp_json, "Window", ntohs(tcph->window));
            cJSON_AddNumberToObject(tcp_json, "Checksum", ntohs(tcph->check));
            cJSON_AddNumberToObject(tcp_json, "Urgent Pointer", tcph->urg_ptr);
            cJSON_AddStringToObject(packet_json, "Protocol", "TCP");
            cJSON_AddItemToObject(packet_json, "Transport Header", tcp_json);
            break;
        case IPPROTO_UDP:
            udp_json = cJSON_CreateObject();
            udph = (struct udphdr *)(packet + 14 + ipHeader->ip_hl * 4);
            cJSON_AddNumberToObject(udp_json, "Source port", src_port);
            cJSON_AddNumberToObject(udp_json, "Destination port", dest_port);
            cJSON_AddNumberToObject(udp_json, "UDP Length", ntohs(udph->len));
            cJSON_AddNumberToObject(udp_json, "UDP Checksum", ntohs(udph->check));
            cJSON_AddStringToObject(packet_json, "Protocol", "UDP");
            cJSON_AddItemToObject(packet_json, "Transport Header", udp_json);
            break;
        default:
            trans_json = cJSON_CreateObject();
            cJSON_AddStringToObject(packet_json, "Protocol", "Unknown");
            cJSON_AddNumberToObject(trans_json, "Source port", src_port);
            cJSON_AddNumberToObject(trans_json, "Destination port", dest_port);
            cJSON_AddItemToObject(packet_json, "Transport Header", trans_json);
    }

    cJSON_AddStringToObject(packet_json, "Payload", pay);
    pacstr = cJSON_Print(packet_json);

    // Send JSON to Flask app
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5000/packet");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, pacstr);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();

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
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Capturing on interface: %s\n", dev);
    pcap_loop(handle, 0, packet_handler, (unsigned char *)dev);
    pcap_close(handle);

    return 0;
}
