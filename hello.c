#include <stdio.h>
#include <pcap.h>

int main() {
    char *dev, errbuf[256];

    dev = pcap_lookupdev(dev);
    if (dev == NULL) {
        fprintf(stderr, "can not find device!", errbuf);
        return 1;
    }

    printf("Dev is: %s\n", dev);
    return 0;
}

