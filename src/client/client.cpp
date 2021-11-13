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

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define SUCCESS 0
#define ARG_ERROR 1
#define ERROR 2
#define INTERNAL_ERR 99

//TODO na toto sa pozriet a nadefinovat to lepsie
#define PORTNUM 32323
#define ADDRESSSTR "127.0.0.1"
#define MAXDATASIZE 100
#define PRT "32323"
#define SIZE 1000


struct user {
    std::string login;
    std::string passwd_hash;
}; 

struct logged_user {
    std::string login;
    std::string passwd_hash;
    std::string session_hash;
};

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


void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
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
    /* ------------------------- PROCESSING OF CMD ARGUMENTS ------------------------- */
    int nCommands = 0;
    std::vector<std::string> commands {"register", "login", "send", "list", "fetch"};

    int port = 32323;
    std::string address = "127.0.0.1";
    struct sockaddr_in sa; 
    std::string command;
    std::string outgoing_message;

    std::vector<user> registered_users;
    std::vector<logged_user> logged_users;

    // user emil {"emil", "0000"};
    // registered_users.push_back(emil);
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
            command = argv[i];

            if(strcmp(argv[i], "register" ) == 0) {
                // check valid num of args - if argc > i + 2
                if(i+2>=argc) {
                    std::cerr << "error: invalid number of arguments for command register" << "\n";
                    return ARG_ERROR;
                }

                std::string incoming_login = argv[i+1];
                std::string incoming_passwd = argv[i+2];
                std::cout << "Pass before encoding: " << incoming_passwd << "\n";

                // TODO encode to base64
                
                // check if user with same login argv[i+1] is already in table
                for(std::vector<user>::iterator i = registered_users.begin(); i != registered_users.end(); ++i) {
                    if(strcmp(((*i).login).c_str(), incoming_login.c_str()) == 0) {
                        std::cerr << "ERROR: user with same login already registered" << "\n";
                        return ERROR;
                    }
                }

                // create new user and add it to vector registered users
                user User = {incoming_login, incoming_passwd};
                registered_users.push_back(User);

                // concatenate the strings into message for server (register "login" "base64passwd")
                outgoing_message = "(" + command + " \"" + incoming_login + "\" " + "\"" + incoming_passwd + "\"" + ")";
            } else if(strcmp(argv[i], "login" ) == 0) {
                if(i+2>=argc) {
                    std::cerr << "error: invalid number of arguments for command login" << "\n";
                    return ARG_ERROR;
                } 

                std::string incoming_login = argv[i+1];
                std::string incoming_passwd = argv[i+2];
                // TODO encode to base64
                // TODO najskor treba poslat outgoing message a zistit od serveru session hash, potom takehoto usera vytvorit a pridat do tabulky
                // check if user with same login argv[i+1] is already in table
                for(std::vector<logged_user>::iterator i = logged_users.begin(); i != logged_users.end(); ++i) {
                    if(strcmp(((*i).login).c_str(), incoming_login.c_str()) == 0) {
                        std::cerr << "ERROR: user already logged in" << "\n";
                        return ERROR;
                    }
                } 

                logged_user User = {incoming_login, incoming_passwd, "Unknown"}; //TODO session hash
                logged_users.push_back(User);

                outgoing_message = "(" + command + " \"" + incoming_login + "\" " + "\"" + incoming_passwd + "\"" + ")";
                std::cout << outgoing_message << "\n";
            }
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

            if(strcmp(argv[i+1], "localhost" ) == 0) {
                address = "127.0.0.1";
            } else if(!(isIPv4 || isIPv6)) {
                std::cerr << "error: invalid ip address or invalid use of options:" << address << "\n";
                return ARG_ERROR; 
            }
        }

        /*todo check if valid login was entered, if user isn't already registered, and if correct number of args was entered*/
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
    /* ------------------------------------------------------------------------------- */

    // int sockfd, numbytes;  
    // char buf[MAXDATASIZE];
    // struct addrinfo hints, *servinfo, *p;
    // int rv;
    // char s[INET6_ADDRSTRLEN];

    // memset(&hints, 0, sizeof hints);
    // hints.ai_family = AF_UNSPEC;
    // hints.ai_socktype = SOCK_STREAM;

    // if ((rv = getaddrinfo(ADDRESSSTR, PRT, &hints, &servinfo)) != 0) {
    //     fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    //     return 1;
    // }


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
    // for(p = servinfo; p != NULL; p = p->ai_next) {
    //     if ((sockfd = socket(p->ai_family, p->ai_socktype,
    //             p->ai_protocol)) == -1) {
    //         perror("client: socket");
    //         continue;
    //     }

    //     if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
    //         close(sockfd);
    //         perror("client: connect");
    //         continue;
    //     }

    //     break;
    // }

    // if (p == NULL) {
    //     fprintf(stderr, "client: failed to connect\n");
    //     return 2;
    // }

    // inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
    //         s, sizeof s);
    // printf("client: connecting to %s\n", s);

    // freeaddrinfo(servinfo); // all done with this structure

    // if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
    //     perror("recv");
    //     exit(1);
    // }

    // buf[numbytes] = '\0';

    // printf("client: received '%s'\n",buf);

    // close(sockfd);
    return SUCCESS;
}