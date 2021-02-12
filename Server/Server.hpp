//
// Created by gabriele on 16/01/21.
//

#ifndef FOUR_IN_A_ROW_SERVER_HPP
#define FOUR_IN_A_ROW_SERVER_HPP

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include "../Utility/SecureConnectionServlet.h"
#include "../rapidxml-1.13/rapidxml.hpp"
#include "../Utility/utils.h"
#include "../Utility/Headers.h"
using namespace std;
using namespace rapidxml;

struct User{
    string Username;
    string PublicKeyPath;
    EVP_PKEY *pubK;
    bool logged = false;

    sockaddr_in addr;
    int client_socket;
    uint16_t onListenPort = 0;


    unsigned char* nonce_client = nullptr;
    unsigned char* nonce_server = nullptr;
    EVP_PKEY* dh_connectionKeyPair = nullptr;
    EVP_PKEY* dh_pubkey = nullptr;
    unsigned char* Kses = nullptr;
    size_t Kses_len = 0;
    unsigned char* iv = nullptr;

    bool inGame = false;

    User* next = nullptr;
};

struct WaitingClientConnection {
    struct sockaddr_in addr;
    int client_socket;

};

#define BUFF_MAX_SIZE 4096
#define BACKLOG_SIZE 64
#define MAX_NUMBER_OF_CLIENTS 30
#define USERNAME_SIZE_MAX 30
#define NONCESIZE 16


class Server{
    string DB_file_path;
    string Certificate_path;
    string PrivateKey_path;
    string netParams_path;

    X509* cert;
    EVP_PKEY* prvkey;

    struct sockaddr_in srv_addr;

    User* listOfUsers = nullptr;
    static SecureConnectionServlet servlet_;

public:
    Server(string DB_file, string certificate_path, string privateKey_path, string netParams_path){
        this->DB_file_path = DB_file;
        this->Certificate_path = certificate_path;
        this->PrivateKey_path = privateKey_path;
        this->netParams_path = netParams_path;
        cout << "\033[1;32m";
        std::cout<<"************************************"<<endl;
        fetchUsersFromFile();
        fetchCertificateFromFile();
        fetchPrivateKeyFromFile();
        fetchAndSetNetParams();
        std::cout<<"************************************"<<endl;
        cout <<"\033[0m\n";
    }

    void printListofUsers();
    void printListofLoggedUsers();
    void printServerNetworkParams();
    void start();
private:
    //UTILITIES FOR INIT
    void fetchAndSetNetParams();
    void fetchUsersFromFile();
    void fetchCertificateFromFile();
    void fetchPrivateKeyFromFile();

    //UTILITIES TO FETCH CLIENTS INFO
    User* searchConnectedClientBySocketNumber(int sock_num);
    User* searchConnectedClientByUsername(string username);
    EVP_PKEY* fetchPublicKey(string path);

    //UTILITIES TO EXTRACT INFO FROM
    int extractMessageType(unsigned char* msg);
    unsigned char* extractIDFromMsg(unsigned char* msg);

    int searchNewClientInWaitingListBySocketNumber(vector<WaitingClientConnection> v, int sock_num);
    unsigned char* createChallengeInfoMsg(User* to, User* peer, size_t& msg_len);

    //UTILITIES TO CONTROLL SERVER
    void printCommands();
    void checkCommand(string com);
    bool handleMessages(unsigned char* msg, size_t msg_len, User* client);
    unsigned char* serializeListOfLoggedUsers(size_t& len);
};


#endif //FOUR_IN_A_ROW_SERVER_HPP