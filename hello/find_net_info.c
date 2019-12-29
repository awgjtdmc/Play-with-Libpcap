#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define DEV_LEN 128

char* find_first_dev() {

    pcap_if_t *alldevs = NULL;
    static char dev_name[100];
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    if (alldevs == NULL) {
        fprintf(stderr, "\nNo interfaces found! Make sure WinPcap is installed. for %s\n", errbuf);
        exit(1);
    }

    strncpy(dev_name, alldevs->name, DEV_LEN);

    pcap_freealldevs(alldevs);
    return dev_name;
}


int main(int argc, char *argv[]) {

    char *dev = find_first_dev();
    printf("First dev is %s\n", dev);
    int ret = 0;
    char *net;
    char *mask;
    char errbuf[256];
    bpf_u_int32 netp;
    bpf_u_int32 netmask;
    struct in_addr addr;
    ret = pcap_lookupnet(dev, &netp, &netmask, errbuf);
    if (ret == -1) {
        perror("lookupnet error");
        exit(1);
    }
    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (net == NULL) {
        perror("inet_ntoa error");
        exit(1);
    }
    printf("IP is:%s\n", net);

    addr.s_addr = netmask;
    mask = inet_ntoa(addr);
    if (mask == NULL) {
        perror("inet_ntoa error");
        exit(2);
    }
    printf("mask is:%s\n", mask);
    return 0;
}

