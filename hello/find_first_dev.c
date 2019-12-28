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
    printf("%s", dev);
    return 0;
}

