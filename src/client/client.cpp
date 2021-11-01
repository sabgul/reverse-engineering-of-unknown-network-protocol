/*
*   Client source code. (main)
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <ctype.h>
#define SUCCESS 0
#define ARG_ERROR 1
#define FINDALLDEVS_ERR 2
#define LOOKUP_ERR 3
#define PCAPOPEN_ERR 4
#define FILTER_ERR 5
#define INTERNAL_ERR 99

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define ICMP_PROTOCOL 1

void displayHelp() {
    fprintf(stdout, "\n---------------------- GUIDE - PACKET SNIFFER ----------------------\n"
                    "DESCRIPTION: \n"
                    "ACCEPTED PARAMETERS: \n"
                    "ERROR CODES: \n"
                    "   1                - invalid arguments\n"
                    "--------------------------------------------------------------------\n\n");
}

int processArguments() {
    return SUCCESS;
}

int main(int argc, char **argv) {
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            displayHelp();
            return SUCCESS;
    }


    return SUCCESS;
}