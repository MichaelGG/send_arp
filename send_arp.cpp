#include "stdafx.h"
#include <pcap.h>

struct arp_packet {
    char  eth_dst_addr[6];
    char  eth_src_addr[6];
    short eth_frame_type;
    short htype;
    short ptype;
    char  hlen;
    char  plen;
    short oper;
    char  sha[6];
    char  spa[4];
    char  tha[6];
    char  tpa[4];
    char  trail[18];
};

static char errbuf[PCAP_ERRBUF_SIZE];

void print_list() 
{
    pcap_if_t *devs;
    if (-1 == pcap_findalldevs(&devs, errbuf))
    {
        printf("Couldn't open device list: %s\n", errbuf);
        exit(1);
    }
    if (!devs) {
        printf("No devices found.");
        exit(1);
    }
    for (pcap_if_t *d = devs; d; d = d->next) {
        printf("%s (%s)\n", d->name, d->description);
    }
    pcap_freealldevs(devs);
}
void set_mac(char* str, char* dstx)
{
    short* dst = (short*)dstx;
    for(int i = 0; i < 3; i++) 
    {
        sscanf(str + i * 4, "%4hx", dst + i);
        dst[i] = htons(dst[i]);
    }
}
void send_packet(char *dev, char *srcmac, char *dstmac, char* sendmac, char* targetmac, char *sendip, char* targetip)
{
    struct arp_packet p = {0};
	
    set_mac(dstmac, p.eth_dst_addr);
    set_mac(srcmac, p.eth_src_addr);
    p.eth_frame_type = htons(0x0806);
    p.htype = htons(0x0001);
    p.ptype = htons(0x0800);
    p.hlen = 6;
    p.plen = 4;
    p.oper = htons(0x0002);
    set_mac(sendmac, p.sha);
    set_mac(targetmac, p.tha);
    *(u_long*)p.spa = inet_addr(sendip);
    *(u_long*)p.tpa = inet_addr(targetip);

    pcap_t *pc;
    if(!(pc = pcap_open_live(dev, 65535, 1, 1, errbuf)))
    {
        printf("Couldn't open device %s: %s", dev, errbuf);
        exit(1);
    }
    if(0 != pcap_sendpacket(pc, ((u_char*)&p), sizeof(arp_packet)))
    {
        printf("Error sending packet: %s", pcap_geterr(pc));
        exit(1);
    }
    else
    {
        printf("ARP packet sent.");
    }
    pcap_close(pc);
}

int main(int argc, char* argv[])
{
    char usage[] = "Usage: send_arp <device> <src mac> <dst mac> <sender mac> <target mac> <sender ip> <target ip>\n";
    if (argc != 8) 
    {
        printf(usage);
        print_list();
        exit(1);
    }
    if (strlen(argv[2]) != 12 || strlen(argv[3]) != 12) 
    {
        printf("Invalid MAC addresses.\n");
        printf(usage);
        exit(1);
    }
    send_packet(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    return 0;
}

