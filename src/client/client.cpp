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
#include <fstream>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <regex>

#define SUCCESS 0
#define ARG_ERROR 1
#define ERROR 2
#define CONNECTION_ERROR -1
#define INTERNAL_ERR 99

//TODO na toto sa pozriet a nadefinovat to lepsie
#define PORT 32323
#define ADDRESSSTR "127.0.0.1"
#define MAXDATASIZE 100
#define SIZE 1000


struct user {
    std::string login;
    std::string passwd_hash;
};

struct message {
    std::string id;
    std::string login;
    std::string subject;
};

//TODO kontrola, ci je user uz logged in a registered je zbytocna, pretoze to mi povie server

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

// TODO prerobit a ocitovat
char* base64Encoder(char input_str[], int len_str)
{
   
    // Character set of base64 encoding scheme
    char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      
    // Resultant string
    char *res_str = (char *) malloc(SIZE * sizeof(char));
      
    int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp;
    int i, j, k = 0;
      
    // Loop takes 3 characters at a time from
    // input_str and stores it in val
    for (i = 0; i < len_str; i += 3)
        {
            val = 0, count = 0, no_of_bits = 0;
  
            for (j = i; j < len_str && j <= i + 2; j++)
            {
                // binary data of input_str is stored in val
                val = val << 8;
                  
                // (A + 0 = A) stores character in val
                val = val | input_str[j];
                  
                // calculates how many time loop
                // ran if "MEN" -> 3 otherwise "ON" -> 2
                count++;
              
            }
  
            no_of_bits = count * 8;
  
            // calculates how many "=" to append after res_str.
            padding = no_of_bits % 3;
  
            // extracts all bits from val (6 at a time)
            // and find the value of each block
            while (no_of_bits != 0)
            {
                // retrieve the value of each block
                if (no_of_bits >= 6)
                {
                    temp = no_of_bits - 6;
                      
                    // binary of 63 is (111111) f
                    index = (val >> temp) & 63;
                    no_of_bits -= 6;        
                }
                else
                {
                    temp = 6 - no_of_bits;
                      
                    // append zeros to right if bits are less than 6
                    index = (val << temp) & 63;
                    no_of_bits = 0;
                }
                res_str[k++] = char_set[index];
            }
    }
  
    // padding is done here
    for (i = 1; i <= padding; i++)
    {
        res_str[k++] = '=';
    }
  
    res_str[k] = '\0';
  
    return res_str;
}

/**
 * @brief Function splits the input string into tokens separated by delimiter
 * 
 * @param s - string to be split
 * @param delim - delimiter splitting the tokens
 * @return std::vector<std::string> - vector of tokens
 * 
 * @ref https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
 */
std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss (s);
    std::string item;

    while(getline (ss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

int main (int argc, char **argv) {
    /* ------------------------- PROCESSING OF CMD ARGUMENTS ------------------------- */
    int nCommands = 0;
    std::vector<std::string> commands {"register", "login", "send", "list", "fetch", "logout"};

    int port = 32323;
    std::string address = "127.0.0.1";
    struct sockaddr_in sa; 
    std::string command;
    std::string outgoing_message;

    std::vector<user> registered_users;
    std::string login_hash;
    std::string final_login_hash;

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
            /* ------------------------- REGISTER ------------------------- */
                // check valid num of args - if argc > i + 2
                if(i+2>=argc) {
                    std::cerr << "error: invalid number of arguments for command register" << "\n";
                    return ARG_ERROR;
                }

                std::string incoming_login = argv[i+1];
                std::string incoming_passwd = argv[i+2];

                // TODO encode to base64
                
                // check if user with same login argv[i+1] is already in table
                for(std::vector<user>::iterator i = registered_users.begin(); i != registered_users.end(); ++i) {
                    if(strcmp(((*i).login).c_str(), incoming_login.c_str()) == 0) {
                        std::cerr << "ERROR: user with same login already registered" << "\n";
                        return ERROR;
                    }
                }
                int len_str = incoming_passwd.length();
                char pass_str[len_str + 1];
                strcpy(pass_str, incoming_passwd.c_str());
                incoming_passwd = base64Encoder(pass_str, len_str);
                // create new user and add it to vector registered users
                user User = {incoming_login, incoming_passwd};
                registered_users.push_back(User);
                
                // concatenate the strings into message for server (register "login" "base64passwd")
                outgoing_message = "(" + command + " \"" + incoming_login + "\" " + "\"" + incoming_passwd + "\"" + ")";
            } else if(strcmp(argv[i], "login" ) == 0) {
                /* ------------------------- LOGIN ------------------------- */
                if(i+2>=argc) {
                    std::cerr << "error: invalid number of arguments for command login" << "\n";
                    return ARG_ERROR;
                } 

                std::string incoming_login = argv[i+1];
                std::string incoming_passwd = argv[i+2];
                // TODO encode to base64
                int len_str = incoming_passwd.length();
                char pass_str[len_str + 1];
                strcpy(pass_str, incoming_passwd.c_str());
                incoming_passwd = base64Encoder(pass_str, len_str);

                outgoing_message = "(" + command + " \"" + incoming_login + "\" " + "\"" + incoming_passwd + "\"" + ")";
                std::cout << outgoing_message << "\n";

            } else if(strcmp(argv[i], "send" ) == 0) {
            /* ------------------------- SEND ------------------------- */
                if(i+3>=argc) {
                    std::cerr << "error: invalid number of arguments for command login" << "\n";
                    return ARG_ERROR;
                }

                std::ifstream t("login-token");
                std::stringstream login_hash_token;
                login_hash_token << t.rdbuf();

                outgoing_message = "(" + command + " \"" + login_hash_token.str() + "\"" + " \"" + argv[i+1] + "\"" + " \"" + argv[i+2] + "\"" + " \"" +argv[i+3] + "\"" +")";
            } else if(strcmp(argv[i], "list") == 0) {
            /* ------------------------- LIST ------------------------- */
                std::ifstream t("login-token");
                std::stringstream login_hash_token;
                login_hash_token << t.rdbuf();
                
                outgoing_message = "(" + command + " \"" + login_hash_token.str() + "\"" + ")";
            } else if(strcmp(argv[i], "fetch") == 0) {
            /* ------------------------- FETCH ------------------------- */
                if(i+1>=argc) {
                    std::cerr << "error: invalid number of arguments for command login" << "\n";
                    return ARG_ERROR;
                }

                // TODO check if argument is a number
                std::ifstream t("login-token");
                std::stringstream login_hash_token;

                login_hash_token << t.rdbuf();
                outgoing_message = "(" + command + " \"" + login_hash_token.str() + "\" " + argv[i+1] +")";
            } else if(strcmp(argv[i], "logout") == 0) {
            /* ------------------------ LOGOUT ------------------------ */
                std::ifstream t("login-token");
                std::stringstream login_hash_token;
                login_hash_token << t.rdbuf();

                outgoing_message = "(" + command + " \"" + login_hash_token.str() + "\"" + ")";
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

    } 

    if(nCommands > 1) {
        std::cerr << "error: single command allowed" << "\n";
        return ARG_ERROR;
    } else if(nCommands == 0) {
        std::cerr << "error: no command specified" << "\n";
        return ARG_ERROR;
    }
    /* ------------------------------------------------------------------------------- */

    // TODO OCITOVAT
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    std::string buffer_copy;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "error: socket creation error." << "\n";
        return CONNECTION_ERROR; 
    } 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        std::cerr << "error: address error." << "\n";
        return CONNECTION_ERROR; 
    }

    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "error: connection failed." << "\n";
        return CONNECTION_ERROR; 
    }

    send(sock, outgoing_message.c_str(), outgoing_message.length(), 0);

    valread = read(sock, buffer, 1024);
    
    buffer_copy = buffer;
    if(strcmp(command.c_str(), "register" ) == 0) {
        std::vector<std::string> response = split(buffer, '\"');

        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return ERROR;
        }
    } else if(strcmp(command.c_str(), "login" ) == 0) {
        /* splits the response from server into chunks conatining login token and state of operation*/
        std::vector<std::string> response = split(buffer, '\"');

        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
            login_hash = response.at(3);
            std::ofstream tokenFile;
            tokenFile.open("login-token");
            tokenFile << login_hash;
            tokenFile.close();
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return ERROR;
        }
    } else if(strcmp(command.c_str(), "send" ) == 0) {
        std::vector<std::string> response = split(buffer, '\"');

        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return ERROR;
        }
    } else if(strcmp(command.c_str(), "list" ) == 0) {
        if(strcmp(buffer, "(ok ())") == 0) {
            std::cout << "INFO: server responded with empty message.\n";
            return SUCCESS;
        }

        std::vector<std::string> response = split(buffer, ' ');
        if(strcmp(response.at(0).c_str() ,"(ok") == 0) {
            std::cout << "SUCCESS: \n";
            buffer_copy.erase(0,5);
            buffer_copy.erase(buffer_copy.length()-2, buffer_copy.length());

            std::vector<std::string> listed_messages = split(buffer_copy, ')');
            listed_messages.at(0).erase(0,1);
            std::vector<std::string> first_message_parts = split(listed_messages.at(0), '\"');
            first_message_parts.at(0).erase(first_message_parts.at(0).length()-1, first_message_parts.at(0).length());
            std::cout << first_message_parts.at(0) << ": \n";
            std::cout << "  From: " << first_message_parts.at(1) << "\n";
            std::cout << "  Subject: " << first_message_parts.at(3) << "\n";

            for(int i = 1; i < listed_messages.size(); i++) {
                listed_messages.at(i).erase(0,2);
                std::vector<std::string> message_parts = split(listed_messages.at(i), '\"');
                message_parts.at(0).erase(message_parts.at(0).length()-1, message_parts.at(0).length());
                std::cout << message_parts.at(0) << ": \n";
                std::cout << "  From: " << message_parts.at(1) << "\n";
                std::cout << "  Subject: " << message_parts.at(3) << "\n";
            }

        } else {
            std::cerr << "ERROR: listing of sent messages failed.\n";
            return ERROR;
        }

    } else if(strcmp(command.c_str(), "fetch" ) == 0) {
        std::vector<std::string> response = split(buffer, ' ');
        if(strcmp(response.at(0).c_str() ,"(ok") == 0) {
            std::cout << "SUCCESS: \n\n";
            buffer_copy.erase(0,6);
            buffer_copy.erase(buffer_copy.length()-2, buffer_copy.length());

            std::vector<std::string> fetched_parts = split(buffer_copy, '\"');

            std::cout << "From: " << fetched_parts.at(0) << "\n";
            std::cout << "Subject: " << fetched_parts.at(2) << "\n\n";

            std::cout << fetched_parts.at(4);
        } else {
            std::cerr << "ERROR: listing of sent messages failed.\n";
            return ERROR;
        }

    } else if ((strcmp(command.c_str(), "logout" ) == 0)) {
        std::vector<std::string> response = split(buffer, '\"');
        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return ERROR;
        }
    }

    return SUCCESS;
}
