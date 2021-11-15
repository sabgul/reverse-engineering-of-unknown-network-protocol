/*
*   Client source code. (main)
*
*   Author: Sabina Gulcikova
*           xgulci00@stud.fit.vutbr.cz
*/
#include "client.hpp"

/**
 * Function displays help and usage of the script if -h or --help option was used
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
 * Function checks if array contains specified string
 */
bool in_array(const std::string &value, const std::vector<std::string> &array)
{
    return std::find(array.begin(), array.end(), value) != array.end();
}

/**
 * Function encodes the input string into base64
 * 
 * This portion of code was inspired by:
 * https://www.geeksforgeeks.org/encode-ascii-string-base-64-format/
 */
std::string encodeTobase64(char input_str[], int len_str) {

    char base64set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
      
    int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp;
    int k = 0;

    for(int i = 0; i < len_str; i += 3) {
        val = 0, count = 0;
  
        for(int j = i; j < len_str && j <= i + 2; j++) {
            val = val << 8;
            val = val | input_str[j];
            count++;
        }
  
        no_of_bits = count * 8;
        while(no_of_bits != 0) {
            if(no_of_bits >= 6) {
                temp = no_of_bits - 6; /* 63 in binary 111111 */
                index = (val >> temp) & 63;
                no_of_bits -= 6;        
            } else {
                temp = 6 - no_of_bits;
                index = (val << temp) & 63;
                no_of_bits = 0;
            }
            result = result + base64set[index];
        }
    }

    padding = (count * 8) % 3;
    for(int i = 1; i <= padding; i++) {
        result = result + '=';
    }

    return result;
} 

/**
 * Checks if valid number of commands was entered
 */
int checkNumOfCommands(int nCommands) {
    if(nCommands > 1) {
        std::cerr << "error: single command allowed" << "\n";
        return error_codes::EC_ARG_ERROR;
    } else if(nCommands == 0) {
        std::cerr << "error: no command specified" << "\n";
        return error_codes::EC_ARG_ERROR;
    } else {
        return error_codes::EC_SUCCESS;
    }
}

/**
 * Function splits the input string into tokens separated by delimiter
 * 
 * This function was inspired by:
 *  https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
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

/*
* Function processes the response obtained from server and displays the data
*/
int servResponse(std::string command, char *buffer, std::string login_hash, std::string buffer_copy) {
    if(strcmp(command.c_str(), "register" ) == 0) {
    /* ------------------------- REGISTER ------------------------- */
        std::vector<std::string> response = split(buffer, '\"');

        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return error_codes::EC_ERROR;
        }
    } else if(strcmp(command.c_str(), "login" ) == 0) {
    /* ------------------------- LOGIN ---------------------------- */
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
            return error_codes::EC_ERROR;
        }
    } else if(strcmp(command.c_str(), "send" ) == 0) {
    /* ------------------------- SEND ---------------------------- */
        std::vector<std::string> response = split(buffer, '\"');

        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return error_codes::EC_ERROR;
        }
    } else if(strcmp(command.c_str(), "list" ) == 0) {
    /* ------------------------- LIST ---------------------------- */
        if(strcmp(buffer, "(ok ())") == 0) {
            std::cout << "INFO: server responded with empty message.\n";
            return error_codes::EC_SUCCESS;
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
            return error_codes::EC_ERROR;
        }

    } else if(strcmp(command.c_str(), "fetch" ) == 0) {
    /* ------------------------- FETCH ---------------------------- */
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
            return error_codes::EC_ERROR;
        }

    } else if ((strcmp(command.c_str(), "logout" ) == 0)) {
    /* ------------------------- LOGOUT --------------------------- */
        std::vector<std::string> response = split(buffer, '\"');
        if(strcmp(response.at(0).c_str() ,"(ok ") == 0) {
            std::cout << "SUCCESS: "<< response.at(1) << "\n";
        } else {
            std::cerr << "ERROR: "<< response.at(1) << "\n";
            return error_codes::EC_ERROR;
        }
    /* ------------------------------------------------------------ */
    }
    return error_codes::EC_SUCCESS;
}


int main(int argc, char **argv) {
    int nCommands = 0;
    int isIPv4, isIPv6;
    int operandsNum;
    int port = 32323;
    std::vector<std::string> commands {"register", "login", "send", "list", "fetch", "logout"};
    
    struct sockaddr_in sa; 
    std::string address = "127.0.0.1";
    std::string command;
    std::string outgoing_message;

    std::string login_hash;
    std::string final_login_hash;

    /* ---------------------------- PROCESSING OF ARGUMENTS ------------------------------ */

    if(argc == 1) {
        std::cerr << "error: client expects <command> [<args>] ... \n       0 arguments given \n       see '-h', or '--help'" << "\n";
        return error_codes::EC_ARG_ERROR;
    } 

    /* -- Checking the validity of arguments and creation of request string */
    for(int i = 1; i < argc; i++) {
        if(strcmp( argv[i], "-h" ) == 0 || strcmp( argv[i], "--help" ) == 0)  {
            displayHelp();
            return error_codes::EC_SUCCESS;
        } 

        if(in_array(argv[i], commands)) {
            nCommands++;
            command = argv[i];
            
            if(strcmp(argv[i], "register" ) == 0) {
            /* ------------------------- REGISTER ------------------------- */
                if(i+2>=argc) {
                    std::cerr << "error: invalid number of arguments for command register" << "\n";
                    return error_codes::EC_ARG_ERROR;
                }

                std::string incoming_login = argv[i+1];
                std::string incoming_passwd = argv[i+2];

                int len_str = incoming_passwd.length();
                char pass_str[len_str + 1];
                strcpy(pass_str, incoming_passwd.c_str());
                incoming_passwd = encodeTobase64(pass_str, len_str);
                
                /* concatenate the strings into message for server (register "login" "base64passwd") */
                outgoing_message = "(" + command + " \"" + incoming_login + "\" " + "\"" + incoming_passwd + "\"" + ")";
            } else if(strcmp(argv[i], "login" ) == 0) {
            /* ------------------------- LOGIN ------------------------- */
                if(i+2>=argc) {
                    std::cerr << "error: invalid number of arguments for command login" << "\n";
                    return error_codes::EC_ARG_ERROR;
                } 

                std::string incoming_login = argv[i+1];
                std::string incoming_passwd = argv[i+2];
                
                int len_str = incoming_passwd.length();
                char pass_str[len_str + 1];
                strcpy(pass_str, incoming_passwd.c_str());
                incoming_passwd = encodeTobase64(pass_str, len_str);

                outgoing_message = "(" + command + " \"" + incoming_login + "\" " + "\"" + incoming_passwd + "\"" + ")";
            } else if(strcmp(argv[i], "send" ) == 0) {
            /* ------------------------- SEND ------------------------- */
                if(i+3>=argc) {
                    std::cerr << "error: invalid number of arguments for command login" << "\n";
                    return error_codes::EC_ARG_ERROR;
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
                    return error_codes::EC_ARG_ERROR;
                }

                int test;
                if(sscanf(argv[i+1], "%d", &test) != 1) {
                    std::cerr << "error: invalid fetch id" << "\n";
                    return error_codes::EC_ARG_ERROR; 
                }

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
            /* -------------------------------------------------------- */   
            } 
        } 

        /* --port */
        if(strcmp(argv[i], "-p" ) == 0 || strcmp(argv[i], "--port" ) == 0) {
            if(sscanf(argv[i+1], "%d", &port) != 1) {
                std::cerr << "error: invalid characters in port" << "\n";
                return error_codes::EC_INTERNAL_ERR; 
            } 

            if(port < 0 || port > 65635) {
                std::cerr << "error: invalid port number or invalid use of options" << "\n";
                return error_codes::EC_ARG_ERROR; 
            }
        } 

        /* --address */
        if(strcmp(argv[i], "-a" ) == 0 || strcmp(argv[i], "--address" ) == 0) {
            address = argv[i+1];
            
            isIPv4 = (inet_pton(AF_INET, address.c_str(), &(sa.sin_addr)) != 1) ? 0 : 1;
            isIPv6 = (inet_pton(AF_INET6, address.c_str(), &(sa.sin_addr)) != 1) ? 0 : 1;

            if(strcmp(argv[i+1], "localhost" ) == 0) {
                address = "127.0.0.1";
            } else if(!(isIPv4 || isIPv6)) {
                std::cerr << "error: invalid ip address or invalid use of options:" << address << "\n";
                return error_codes::EC_ARG_ERROR; 
            }
        }

    } 

    int code = checkNumOfCommands(nCommands);
    if(code != error_codes::EC_SUCCESS) {
        return code;
    }

    /* ------------------------------------------------------------------------------------ */

    /* -------------------- ESTABLISHMENT OF THE TCP COMMUNICATION ------------------------ */

    /**
     * This portion of code was inspired by https://www.geeksforgeeks.org/socket-programming-cc/
     */
    std::string buffer_copy;
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[MAX_SIZE] = {0};
    int domain = AF_INET;
    
    /* -- Sets up proper communication for IPv4 or IPv6 */
    if(isIPv4 == 1) {
        domain = AF_INET;
    } else {
        domain = AF_INET6;
    }

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "error: socket creation error." << "\n";
        return error_codes::EC_CONNECTION_ERROR; 
    } 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET, address.c_str(), &serv_addr.sin_addr)<=0) {
        std::cerr << "error: address error." << "\n";
        return error_codes::EC_CONNECTION_ERROR; 
    }

    /* -- Try to connect */
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        std::cerr << "error: connection failed." << "\n";
        return error_codes::EC_CONNECTION_ERROR; 
    }
    /* -- Send request */
    send(sock, outgoing_message.c_str(), outgoing_message.length(), 0); 
    /* -- Read response */
    valread = read(sock, buffer, MAX_SIZE);
    close(sock); 
    /* -------------------------------------------------------------------------------- */

    /* ------------- COMMUNICATION WITH SERVER BASED ON SPECIFIED COMMAND ------------- */
    buffer_copy = buffer;
    int serv_communication = servResponse(command, buffer, login_hash, buffer_copy);
    if(serv_communication != error_codes::EC_SUCCESS) {
        return serv_communication;
    }

    /* -------------------------------------------------------------------------------- */
    return error_codes::EC_SUCCESS;
}
