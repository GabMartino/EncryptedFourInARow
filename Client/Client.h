//
// Created by gabriele on 16/01/21.
//

#ifndef FOUR_IN_A_ROW_CLIENT_H
#define FOUR_IN_A_ROW_CLIENT_H

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../rapidxml-1.13/rapidxml.hpp"
#include <stdio.h>
#include <unistd.h>
#include "../Utility/SecureConnectionServlet.h"
#include <netinet/in.h>
#include "../Utility/utils.h"
#include "../Utility/Headers.h"
#include "../Four_in_a_row_game/Four_in_a_row_game.h"

using namespace std;
using namespace rapidxml;
#define BUFF_MAX_SIZE 4096
#define BACKLOG_SIZE 64
#define MAX_NUMBER_OF_CLIENTS 30
#define USERNAME_SIZE_MAX 30
#define NONCESIZE 16
#define MSGCODESIZE 1

class Client{
    //My info
    string DB_path_file;
    string privateKey_path;
    string serverParams_path;
    string username;
    string password;
    EVP_PKEY* prvkey = nullptr;
    sockaddr_in my_addr;


    //SERVER SESSION INFO
    sockaddr_in server_params;
    int socket_;
    unsigned char* nonce = nullptr;
    unsigned char* nonceS = nullptr;
    EVP_PKEY* my_dh_keys;
    EVP_PKEY* server_dh_pub_key;
    unsigned char* Kses = nullptr;
    size_t Kses_len = 0;
    unsigned char* iv = nullptr;

    //CA INFOR
    string ca_certificate_path_file;
    string ca_crl_path_file;
    X509_STORE* store;

    //ADVERSARY INFORMATION
    char adv_username[USERNAME_SIZE_MAX];
    unsigned char* my_nonce = nullptr;
    unsigned char* adv_nonce = nullptr;
    sockaddr_in adv_params;
    int adv_socket = 0;
    EVP_PKEY* adv_pubkey;
    EVP_PKEY* my_dh_game_session_keys = nullptr;
    EVP_PKEY* adv_dh_game_session_pub_key = nullptr;
    unsigned char* game_key = nullptr;
    size_t game_key_len = 0;
    unsigned char* iv_game = nullptr;

    //STATE VARIABLE
    bool inGame = false;
    bool applicant = false;
    vector<string> updatedListOfLoggedUsers;

    static SecureConnectionServlet servlet_ ;
    static Four_in_a_row_game game_;

    timeval* t = nullptr;

public:
    Client(string DB_Users_path, string ca_cert_path_file, string ca_crl_path_file,  string serverParams_path,string Username, string password){
        this->DB_path_file = DB_Users_path;
        this->ca_certificate_path_file = ca_cert_path_file;
        this->ca_crl_path_file = ca_crl_path_file;
        this->serverParams_path = serverParams_path;
        if(Username.size() >=30){
            cerr<<"Username lenght too big"<<endl;
            exit(1);
        }else if(!Username.empty()){
            this->username = Username;
            if(password.size() >= 30){
                cerr<<"Password too big."<<endl;
                exit(1);
            }
            this->password = password;
            store = X509_STORE_new();
            searchUserInFile();
            fetchPrivateKeyFromFile();
            fetchCACertificateAndCRLFromFile();
            fetchAndSetNetParams();
        }
    }
    Client(string DB_Users_path, string ca_cert_path_file, string ca_crl_path_file,  string serverParams_path){
        this->DB_path_file = DB_Users_path;
        this->ca_certificate_path_file = ca_cert_path_file;
        this->ca_crl_path_file = ca_crl_path_file;
        this->serverParams_path = serverParams_path;
    }

    void login();
    bool connectToServer();
    bool authenticate();
    bool start();
private:
    void fetchPrivateKeyFromFile();
    bool searchUserInFile();
    void fetchCACertificateAndCRLFromFile();
    void fetchAndSetNetParams();
    void printCommands();

    void deserializeListOfLoggedUsers(unsigned char* list, size_t list_len);
    void printCommandsInGame();
    int checkCommand(string com);
    int extractMessageType(unsigned char *msg);
    unsigned char* extractIDFromMsg(unsigned char* msg);


    void requireLoggedUsersList();
    void playRequest(string adv_name);
    bool handleServerMsg(unsigned char* msg, size_t len);
    bool handleUserListResponse(unsigned char* msg, size_t len);
    bool handleChallengeRequest(unsigned char* msg, size_t len);
    bool handleChallengeResponse(unsigned char* msg, size_t len);
    bool handleChallengeInfo(unsigned char* msg, size_t len);

    bool handlePeerMsg(unsigned char* msg, size_t len);
    bool handleKeyExchangeUserRequest(unsigned char* msg, size_t len);
    bool handleKeyExchangeUserResponse(unsigned char* msg, size_t len);
    bool handleKeyExchangeUserConfirmation(unsigned char* msg, size_t len);
    bool sendFreeStateToServer();


    void play(bool yourTurn);
    int checkCommandInGame(string com);
    bool sendMove(uint16_t value) ;
    bool sendCloseGame();
    int handleAdvMessage(unsigned char* msg, size_t len, uint16_t& move);
    void closeGameSession();
};

#endif //FOUR_IN_A_ROW_CLIENT_H