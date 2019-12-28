#include <stdio.h>
#include <pcap.h>

// int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
// void pcap_freealldevs(pcap_if_t *alldevs);

int main() {
    char errbuf[256];
    pcap_if_t* alldevsp = NULL;
    pcap_if_t* temp = NULL;
    int res = 0;
    res = pcap_findalldevs(&alldevsp, errbuf);
    printf("res is %d\n", res);

    if (res != 0 || alldevsp == NULL) {
        fprintf(stderr, "pcap_findalldevs return error: %d\n", res);
        return 1;
    }

    temp = alldevsp;
    printf("dev list is :\n");
    while (temp) {
        printf("name:\t %s desc:\t %s\n",
                temp->name, temp->description);
        temp = temp->next;
    }

    pcap_freealldevs(alldevsp);
    return 0;
}

// DESCRIPTION from
// https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html


