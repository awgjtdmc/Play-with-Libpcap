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
    char errbuf[256];
    int ret;
    const u_char* packet;
    struct pcap_pkthdr protocal_header;
    struct ethre_header* eptr;
    pcap_t* pcap_handle;
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "";
    bpf_u_int32 netmask;
    bpf_u_int32 netip;
    u_char *ptr;

    ret = pcap_lookupnet(dev, &netip, &netmask, errbuf);
    if (ret == -1) {
        printf("pcap_lookupnet() error");
        exit(1);
    }
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (pcap_handle == NULL) {
        printf("pcap_open_live error");
        exit(1);
    }

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, netip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    packet = pcap_next(pcap_handle, &protocal_header);
    if (packet == NULL) {
        printf("pcap_next error!\n");
        exit(2);
    }

    printf("Got packet from: %s\n", dev);
    printf("Packet length %d\n", protocal_header.len);
    pcap_close(pcap_handle);

    return 0;
}

