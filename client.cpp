/*
*   Client source code. (main)
*/
#include "client.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <ctype.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>

#define SUCCESS 0
#define ARG_ERROR 1
#define ERROR 2
#define INTERNAL_ERR 99

//TODO na toto sa pozriet a nadefinovat to lepsie
#define PORTNUM 32323
#define ADDRESSSTR "127.0.0.1"


/**
 * @brief Function displays help and usage of the script if -h or --help option was used
 */
void displayHelp() {
    fprintf(stdout, "\n---------------------- HELP - ISA CLIENT ----------------------\n"
                    "USAGE: ./client [ <option> ...] <command> [<args>] ...\n\n"
                    "<option>: \n"
                    "   -a <addr>, --address <addr> \n"
                    "       Server hostname or address to connect to\n"
                    "   -p <port>, --port <port>\n"
                    "       Server port to connect to\n"
                    "   -h, --help\n"
                    "       Display this help\n"
                    "   --\n"
                    "       Do not treat any remaining arguments as a switch (at this level)\n\n"
                    "<command>:\n"
                    "   register <username> <password>\n"
                    "   login <username> <password>\n"
                    "   send <recipient> <subject> <body>\n"
                    "   list\n"
                    "   fetch <id>\n"
                    "   logout\n\n"
                    "ERROR CODES: \n"
                    "   1                - invalid arguments\n"
                    "   2                - error\n"
                    "   99               - internal error\n"
                    "--------------------------------------------------------------------\n\n");
}

/**
 * @brief Function checks if array contains specified string
 */
bool in_array(const std::string &value, const std::vector<std::string> &array)
{
    return std::find(array.begin(), array.end(), value) != array.end();
}

// int processArguments(int argc, char **argv) {
//     return SUCCESS;
// }

// void printShit(int &num) {
//     std::cout << num;
// }

// template<typename T>
// T sumMyVec(std::vector<T> input) {
//     T sum = 0;
//     std::for_each(input.cbegin(), input.cend(), [&](T n){ sum += n; });

//     return sum;
// }

int main (int argc, char **argv) {
    /* ----------------------- PROCESSING OF ENTERED ARGUMENTS ----------------------- */
    int nCommands = 0;
    std::vector<std::string> commands {"register", "login", "send", "list", "fetch"};

    int port = 32323;
    std::string address = "127.0.0.1";
    struct sockaddr_in sa;

    if(argc == 1) {
        std::cerr << "error: client expects <command> [<args>] ... \n       0 arguments given \n       see '-h', or '--help'" << "\n";
        return ARG_ERROR;
    } 

    for(int i = 1; i < argc; i++) {
        if(strcmp( argv[i], "-h" ) == 0 || strcmp( argv[i], "--help" ) == 0)  {
            displayHelp();
            return SUCCESS;
        } 

        if(in_array(argv[i], commands)) {
            nCommands++;
        } 

        /* --port */
        if(strcmp(argv[i], "-p" ) == 0 || strcmp(argv[i], "--port" ) == 0) {
            if(sscanf(argv[i+1], "%d", &port) != 1) {
                std::cerr << "error: converting string to integer failed" << "\n";
                return INTERNAL_ERR; 
            } 

            if(port < 0 || port > 65635) {
                std::cerr << "error: invalid port number or invalid use of options" << "\n";
                return ARG_ERROR; 
            }
        } 

        /* --address */
        if(strcmp(argv[i], "-a" ) == 0 || strcmp(argv[i], "--address" ) == 0) {
            address = argv[i+1];
            
            int isIPv4 = (inet_pton(AF_INET, address.c_str(), &(sa.sin_addr)) != 1) ? 0 : 1;
            int isIPv6 = (inet_pton(AF_INET6, address.c_str(), &(sa.sin_addr)) != 1) ? 0 : 1;

            if(!(isIPv4 || isIPv6)) {
                std::cerr << "error: invalid ip address or invalid use of options:" << address << "\n";
                return ARG_ERROR; 
            }
        }

        /* register */
        /* login */
        /* send */
        /* list */
        /* fetch */

    } 

    if(nCommands > 1) {
        std::cerr << "error: single command allowed" << "\n";
        return ARG_ERROR;
    } else if(nCommands == 0) {
        std::cerr << "error: no command specified" << "\n";
        return ARG_ERROR;
    }
    /* ------------------------------------------------------------------------------ */



    // if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
    //         displayHelp();
    //         return SUCCESS;
    // }
    // int a = 10;
    // int b = 5;
    
    // std::string ahoj = "Ahojky";
    // std::string meno = " Abika";

    // std::string pozdrav = ahoj + meno;
    // std::cout << pozdrav;

    // std::vector<int> skapvec1 = {1, 2, 3, 4, 5};
    // std::vector<float> skapvec2 = {1.1f, 2.f, 3.1f, 4.32f, 5.23f};
    
    // int sum1 = sumMyVec(skapvec1);
    // float sum2 = sumMyVec(skapvec2);

    // std::cout << "before:";
    // std::for_each(skapvec.cbegin(), skapvec.cend(), [](int n){ printShit(n); });
    // std::cout << '\n';
    
    return SUCCESS;
}