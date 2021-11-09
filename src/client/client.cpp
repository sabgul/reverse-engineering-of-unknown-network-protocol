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

#define SUCCESS 0
#define ARG_ERROR 1
#define ERROR 2
#define INTERNAL_ERR 99

//TODO na toto sa pozriet a nadefinovat to lepsie
#define PORTNUM 32323
#define ADDRESSSTR "127.0.0.1"

int port = 32323;
std::string address = "127.0.0.1";

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


int processArguments() {
    return SUCCESS;
}

void printShit(int &num) {
    std::cout << num;
}

template<typename T>
T sumMyVec(std::vector<T> input) {
    T sum = 0;
    std::for_each(input.cbegin(), input.cend(), [&](T n){ sum += n; });

    return sum;
}

int main (int argc, char **argv) {
    if(argc == 1) {
        std::cerr << "error: client expects <command> [<args>] ... \n       0 arguments given \n       see '-h', or '--help'" << "\n";
        return ARG_ERROR;
    }

    if (argv[1] == "-h" || argv[1] == "--help") {
        std::cout << "bichis" << "\n";
        displayHelp();
        return SUCCESS;
    }
    
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