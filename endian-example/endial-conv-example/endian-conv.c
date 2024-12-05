#include  <stdio.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    unsigned short host_port = 0x1234;
    unsigned short net_port;
    unsigned short host_port_recovered;

    unsigned long host_addr = 0x12345678;
    unsigned long net_addr;
    unsigned long host_addr_recovered;

    net_port = htons(host_port);
    net_addr = htonl(host_addr);

    host_port_recovered = ntohs(net_port);
    host_addr_recovered = ntohl(net_addr);

    printf("Host ordered port: %#x\n", host_port);
    printf("Network ordered port: %#x\n", net_port);
    printf("Recovered host ordered port: %#x\n", host_port_recovered);

    printf("Host ordered ip: %#lx\n", host_addr);
    printf("Network ordered ip: %#lx\n", net_addr);
    printf("Recovered host ordered ip: %#lx\n", host_addr_recovered);

    return 0;
}