#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <regex>

#define PORT 32323
#define SIZE 1000
#define MAX_SIZE 1024

namespace error_codes
{
    enum EC
    {
        EC_SUCCESS,
        EC_ARG_ERROR,
        EC_ERROR,
        EC_CONNECTION_ERROR,
        EC_INTERNAL_ERR = 99
    };
};
