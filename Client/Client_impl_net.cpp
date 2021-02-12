//
// Created by gabriele on 16/01/21.
//
#include "Client.h"




bool Client::connectToServer() {
    cout<<GREEN;
    /* Creation of new socket */
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Socket Creation.."<<endl;
    socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_ == -1) {
        fprintf(stderr, "Error creating new socket\n");
        return false;
    }

    /* Creating TCP connection */
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Connection to Server..."<<endl;
    int ret;
    while(-1 == (ret = connect(socket_, (sockaddr*)&server_params, sizeof(server_params)))){
        cout<<"[CLIENT][ERROR] Connection Error."<<endl;
        if(errno == ECONNREFUSED){
            cout<<"[CLIENT][ERROR] Server is not ONLINE."<<endl;
        }
        sleep(1); //Wait one second before retryng
        cout<<"[CLIENT] Connection to Server..."<<endl;
    }

    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Connection established with Server.  "<<inet_ntoa(this->server_params.sin_addr)<<" port: "<<ntohs(server_params.sin_port)<<endl;
    cout<<RESET<<endl;
    return true;
}

bool Client::authenticate() {
    cout<<YELLOW;
    cout<<"-------------------------------------------------"<<endl;
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" STARTING AUTHENTICATION WITH SERVER"<<endl;
    /* ----------------------------------- HELLO REQUEST ------------------------------------------ */
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Sending Hello Request."<<endl;

    /* CREATE AN HELLO REQUEST MESSAGE */
    size_t len;
    unsigned char* msg = servlet_.createHelloRequest(HELLORQST, this->username, this->nonce, this->prvkey, len);
    if(!msg){
        return false;
    }
    /* SEND HELLO REQUEST MESSAGE */
    int ret = sendto(socket_, msg, len, 0, (sockaddr*)&server_params, sizeof(server_params) );
    if(ret == -1){
        cerr<<"Error sending msg"<<endl;
        return false;
    }
    //BIO_dump_fp(stdout,(const char*)msg, len);
    free(msg);
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Hello Request Sent."<<endl;
    //msg = this->servlet_->createHelloAcceptance(this->username, this->prvkey, this->my_dh_keys, this->nonceS, len );

    /* ---------------------------------- RECEIVING HELLO RESPONSE -----------------------------------------*/
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Receiving Hello Response."<<endl;
    socklen_t cli_addr_size = sizeof(server_params);
    unsigned char received_msg[BUFF_MAX_SIZE];
    ret = recvfrom(socket_, received_msg, BUFF_MAX_SIZE, 0, (sockaddr*)&server_params, &cli_addr_size);
    if(ret == -1 ){
        cout<<"[CLIENT] Error receving message"<<strerror(errno)<<endl;
        return false;
    }else if( ret == 0){
        cout<<"[CLIENT] Socket closed"<<strerror(errno)<<endl;
        return false;
    }
    if(extractMessageType(received_msg) == HELLORESP){

        bool ok = this->servlet_.checkHelloResponse(received_msg, ret, store, nullptr, this->server_dh_pub_key, this->nonce, this->nonceS);
        if(!ok){
            cout<<"Error checking Hello Response"<<endl;
            if(this->nonceS != nullptr){
                cout<<"Sending refusing message to server. Closing"<<endl;
                size_t refuse_len;
                unsigned char* refuse = servlet_.createHelloRefuse(HELLOREFUSE, "Server",this->nonceS, nullptr, this->prvkey, refuse_len);
                if(!refuse){
                    cout<<"[SERVER][ERROR] Error creating msg"<<endl;
                }
                int ret = sendto(socket_, refuse, refuse_len, 0, (sockaddr*)&server_params, sizeof(server_params) );
                if(ret == -1){
                    cerr<<"[CLIENT][ERROR] Error sending msg"<<endl;
                    exit(1);
                    return false;
                }
                free(refuse);
            }
        }
        cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Hello Response is ok."<<endl;
    }else if(extractMessageType(received_msg) == HELLOREFUSE){
        bool check = servlet_.checkHelloRefuse(received_msg, ret, this->store, nullptr, this->nonce);
        if(!check){
            cout<<"[ERROR] Hello Refuse message not valid, possible MIM."<<endl;
        }else{
            cout<<"[ERROR] Hello request not accepted from the server. Check the configuration"<<endl;
            exit(1);
        }
    }
    //BIO_dump_fp(stdout,(const char*)received_msg, ret);
    /*-------------------------------- SENDING ACCEPTATION --------------------------------------------------*/
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Sending HELLO ACCEPTANCE"<<endl;
    /* CREATE DH KEYS   */
    this->my_dh_keys = this->servlet_.generateNewDHKeys();
    if(!this->my_dh_keys){
        cout<<"[CLIENT][ERROR] Error Generating DH key"<<endl;
        return false;
    }
    //DERIVE SHARED SECRET
    this->Kses = this->servlet_.deriveSecretDH(this->my_dh_keys, this->server_dh_pub_key, this->Kses_len);
    if(!this->Kses){
        cout<<"[CLIENT][ERROR] Error derivation DH shared key with server."<<endl;
        return false;
    }
    msg = this->servlet_.createHelloAcceptance(HELLOACCEPT, this->username, this->prvkey, this->my_dh_keys, this->nonceS, len );
    if(!msg){
        cout<<"[CLIENT][ERROR] Error creating Hello acceptance msg"<<endl;
    }
    /* SEND HELLO REQUEST MESSAGE */
    ret = sendto(socket_, msg, len, 0, (sockaddr*)&server_params, sizeof(server_params) );
    if(ret == -1){
        cerr<<"[CLIENT][ERROR] Error sending msg"<<endl;
        return false;
    }
    delete[] msg;
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" AUTHENTICATION ACCOMPLISHED."<<endl;
    //close(socket_);
    cout<<RESET<<endl;
    return true;
}

bool Client::start() {
    /**
     * Create a listening socket for player that want to connect
     *
     */
    int onListenSocket;
    int optval;
    /* New socket creation */
    onListenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(onListenSocket <= 0) {
        cerr<<"[ERROR] Error creating new socket"<<endl;
        return false;
    }
    optval = 1;
    int ret = setsockopt(onListenSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if(ret == -1) {
        cerr<<"[ERROR] Error setting SO_REUSEADDR"<<endl;
        return false;
    }
    this->my_addr.sin_family = AF_INET;
    this->my_addr.sin_addr.s_addr = INADDR_ANY;
    //this->my_addr.sin_port = 0;
    ret = bind(onListenSocket, (sockaddr*)&this->my_addr,sizeof(this->my_addr));
    if(ret == -1){
        cerr<<strerror(errno)<<endl;
        cout<<"[ERROR]Error binding the Socket"<<endl;
        exit(1);
    }
    /* Creating backlog queue */
    ret = listen(onListenSocket, BACKLOG_SIZE);
    if(ret == -1) {
        cout<<"[ERROR]Error creating backlog queue, size"<<BACKLOG_SIZE<<endl;
        return false;
    }
    cout<<BOLDGREEN;
    cout<<"[CLIENT] Created an open connection for another user."<<endl;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &this->my_addr.sin_addr, ip, INET_ADDRSTRLEN);
    cout<<"         IP: "<<ip<<" PORT: "<<ntohs(this->my_addr.sin_port)<<endl;
    cout<<RESET<<endl;

    //-------------------------------SEND PORT TO SERVER------------------------
    cout<<BOLDYELLOW;
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Sending OnListen port to server"<<endl;
    //uint16_t port = this->my_addr.sin_port;
    uint16_t port = this->my_addr.sin_port;
    //SEND PORT FOR COMMUNICATION
    size_t len;
    unsigned char* msg = this->servlet_.createAuthenticatedMsg(PORTINFO, this->username, this->Kses, this->iv,
                                                 reinterpret_cast<unsigned char *>(&port), sizeof(uint16_t), len, GCM);
    if(!msg){
        cout<<"[CLIENT][ERROR] Error create msg."<<endl;
        exit(1);
    }

    ret = sendto(socket_, msg, len, 0, (sockaddr*)&server_params, sizeof(server_params) );
    if(ret == -1){
        cerr<<"[CLIENT][ERROR] Error sending msg"<<endl;
        return false;
    }
    free(msg);
    cout<<RESET<<endl;

    cout<<BOLDBLUE<<endl;
    cout<<"------------------------------------------------------------------------------------------------------------------------------------------------"<<endl;
    cout<<"------------------------------------------------------FOUR IN A ROW CONTROL PANEL---------------------------------------------------------------"<<endl;
    cout<<"------------------------------------------------------------------------------------------------------------------------------------------------"<<endl;
    cout<<endl;
    cout<<"TYPE C TO PRINT COMMANDS"<<endl;
    printCommands();

    fd_set readfds;
    int max_sd ;
    int activity;
    string command;
    cin.clear();


    while(1){
        cout<<BOLDBLUE;
        cout<<endl;
        cout<<"["<<this->username<<"]"<<">>";
        cout.flush();
        /**
         *
         * RESET SOCKET LIST
         *
         */
        FD_ZERO(&readfds);//clear the socket set
        FD_SET(socket_, &readfds);// Server socket
        FD_SET(onListenSocket, &readfds);// On listen socket for new adversary request
        FD_SET(STDIN_FILENO, &readfds);//insert the std input in the socket set to read from keyboard eventual command
        max_sd = socket_ > onListenSocket ?  socket_ : onListenSocket;
        if(this->adv_socket > 0){
            FD_SET(this->adv_socket, &readfds);
            if(this->adv_socket > max_sd){
                max_sd = this->adv_socket;
            }
        }

        //printCommands();
        activity = select(max_sd + 1, &readfds, NULL, NULL, this->t);
        if(activity < 0){
            cout<<"[ERROR] Error socket."<<endl;
            cout<<strerror(errno)<<endl;
            return false;
        }else if(activity == 0){
            cout<<"[ERROR] The peer who request to play didn't send the request. Freeing state.."<<endl;
            //The peer who required to play didn't send the request -> get free;
            free(this->t);
            this->t = nullptr;
            cout<<endl;
            sendFreeStateToServer();


        }


        //CHECK WHICH SOCKET HAS BEEN ACTIVATED
        if(FD_ISSET(socket_, &readfds)){//HANDLE MESSAGE FROM SERVER
            cout<<endl;
            //cout<<"["<<this->username<<"]"<<" Message from Server"<<endl;
            unsigned char received_msg[BUFF_MAX_SIZE];
            memset(received_msg, 0, BUFF_MAX_SIZE);
            socklen_t cli_addr_size = sizeof(server_params);
            int ret = recvfrom(socket_, received_msg, BUFF_MAX_SIZE, 0,(sockaddr *) &this->server_params,&cli_addr_size);
            if(ret == -1){cerr<<"[ERROR] Error receiving msg."<<endl; continue;}
            if(ret == 0){cerr<<"[ERROR] Server socket closed."<<endl; FD_CLR(socket_, &readfds); close(socket_);return false;}
            bool ok = handleServerMsg(received_msg, ret);
            if(!ok){
                cout<<"[ERROR] Error handling server msg."<<endl;
            }
        }else if(FD_ISSET(STDIN_FILENO, &readfds)){//HANDLE STDIN COMMAND

            cin>>command;
            if(cin.fail()){
                cin.clear();
                continue;
            }
            if(!command.compare("C")){
                printCommands();
            }else{
                int c = checkCommand(command);
                if(c == -1){
                    cout<<"[ERROR] Command not found."<<endl;
                }else  if(c == 1){
                    requireLoggedUsersList();
                }else if( c == 2){
                    string adv;
                    bool attempt = true; bool found = false;
                    while(attempt){
                        cout<<"Type the Username of the Gamer you want to play with ['EXIT' to go back]:";
                        cin>>adv;
                        if(!cin){
                            cerr<<"Error cin"<<endl;
                            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                            cin.clear();
                            continue;
                        }
                        if(adv.size()> USERNAME_SIZE_MAX){
                            cout<<"Too big username"<<endl;
                            cout<<"Retry"<<endl;
                        }else if(!adv.compare(this->username)){
                            cout<<"You typed your Username."<<endl;
                        }else if(!adv.compare("EXIT")){
                            break;
                        }else{
                            for(unsigned int i = 0; i<updatedListOfLoggedUsers.size(); i++){
                                if(!updatedListOfLoggedUsers.at(i).compare(adv)){
                                    found = true;
                                    attempt = false;
                                    break;
                                }
                            }
                            if(!found){
                                cout<<RED;
                                cout<<"Username not found. If you still didn't do it, please request the list of logged users at least once."<<endl;
                                cout<<RESET<<endl;
                            }
                        }

                    }
                    if(found){
                        playRequest(adv);
                    }
                }else if( c == 3){
                    close(socket_);
                    cout<<"["<<this->username<<"]"<<" EXIT"<<endl;
                    exit(0);
                }
            }


        }else if(FD_ISSET(onListenSocket, &readfds)){//HANDLE NEW INCOMING CONNECTION
            cout<<endl;
            /* Accepting a request arrived at sk, which will be served by cl_sk */
            if(this->adv_socket == 0){
                socklen_t cl_len = sizeof(this->adv_params);
                this->adv_socket = accept(onListenSocket, (sockaddr*)&this->adv_params, &cl_len);
                if(this->adv_socket == -1) {
                    cout<<"[ERROR] Error during the connection"<<endl;
                    break;
                }

                cout<<"Created connection with new peer"<<endl;
            }else{
                cout<<"[ERROR] State not reachable"<<endl;
                exit(1);
            }
        }else if(FD_ISSET(this->adv_socket,&readfds)){//HANDLE COMMAND FROM THE NEW PEER
            cout<<endl;
            cout<<" Message from the peer."<<endl;
            unsigned char received_msg[BUFF_MAX_SIZE];
            memset(received_msg, 0, BUFF_MAX_SIZE);
            socklen_t cli_addr_size = sizeof(this->adv_params);
            int ret = recvfrom(this->adv_socket, received_msg, BUFF_MAX_SIZE, 0,(sockaddr *) &this->adv_params,&cli_addr_size);
            if(ret == -1){cerr<<"[ERROR] Error receiving msg."<<endl; cerr<<strerror(errno)<<endl; exit(1);continue;}
            if(ret == 0){cerr<<"[ERROR] Server socket closed."<<endl; FD_CLR( this->adv_socket, &readfds); close(this->adv_socket); this->adv_socket = 0;return false;}
            bool ok = handlePeerMsg(received_msg, ret);
            if(!ok){
                cout<<"[ERROR] Error handling msg."<<endl;
            }

        }

    }

    return true;
}


void Client::requireLoggedUsersList() {
    cout<<"["<<this->username<<"]"<<" SENDING USERLIST REQUEST"<<endl;
    size_t msg_len = 0;
    unsigned char* msg = this->servlet_.createAuthenticatedMsg(USERLISTRQST, this->username, this->Kses, this->iv, NULL, 0, msg_len, GMAC);
    if(!msg){
        cerr<<"[ERROR] Error creating msg"<<endl;
        return;
    }

    int ret = sendto(socket_, msg, msg_len, 0, (sockaddr*)&server_params, sizeof(server_params) );
    if(ret == -1){
        cerr<<"[ERROR] Error sending msg"<<endl;
    }
    free(msg);
    cout<<"["<<this->username<<"]"<<" USERLIST REQUEST SENT."<<endl;

}

bool Client::handleServerMsg(unsigned char *msg, size_t len) {

    if (extractMessageType(msg) == USERLISTRESP) {
        return handleUserListResponse(msg, len);

    }else if(extractMessageType(msg) == CHLRQST){
        return handleChallengeRequest(msg, len);

    }else if(extractMessageType(msg) == CHLRESP){
        return handleChallengeResponse(msg, len);

    }else if(extractMessageType(msg) == CHLINFO){
        bool check = handleChallengeInfo(msg, len);
        if(applicant and check){
            this->adv_socket = socket(AF_INET, SOCK_STREAM, 0);
            if( this->adv_socket  == -1) {
                fprintf(stderr, "Error creating new socket\n");
                return false;
            }

            /* Creating TCP connection */
            cout<<"["<<this->username<<"]"<<" Connection to User..."<<endl;
            int ret = connect(this->adv_socket, (sockaddr*)&this->adv_params, sizeof(this->adv_params));
            if( ret == -1){
                cout<<"[CLIENT][ERROR] Connection Error."<<endl;
                cout<<strerror(errno)<<endl;
                return false;
            }

            cout<<"["<<this->username<<"]"<<" Connection established with other User."<<endl;
            cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] Sending Key exchange request."<<endl;
            size_t len;
            unsigned char* msg = servlet_.createHelloRequest(KEYEXCHRQST, this->username, this->my_nonce, this->prvkey, len);
            if(!msg){
                return false;
            }
            ret = sendto(this->adv_socket, msg, len, 0, (sockaddr*)&this->adv_params, sizeof(this->adv_params) );
            if(ret == -1){
                cerr<<"Error sending msg"<<endl;
                return false;
            }
            free(msg);
        }else if(!applicant){
            //waint one second for the request of the peer
            this->t = (timeval*)malloc(sizeof(timeval));
            if(this->t == nullptr){
                cout<<"[ERROR] MEM ALLOC"<<endl;
                exit(1);
            }
            this->t->tv_sec = 3;


        }
        return check;
    }else if(extractMessageType(msg) == BUSYPEER) {//THe peer who YOU request to play is busy
        unsigned char* dummy= nullptr; size_t dumy_len = 0;
        bool check = this->servlet_.checkAuthenticatedMsg(msg, len, this->Kses, this->iv, dummy, dumy_len, GMAC);
        if(!check){
            cout<<"[ERROR] Error in checking server's busy peer response."<<endl;
            return false;
        }
        cout<<BOLDRED;
        cout<<"The player who you request to play with is actually busy at this moment. :("<<endl;
        applicant = false;
        return true;
    }else if(extractMessageType(msg) == NOTLOGGEDPEER) {//THe peer who YOU request to play is busy
        unsigned char *dummy = nullptr;
        size_t dumy_len = 0;
        bool check = this->servlet_.checkAuthenticatedMsg(msg, len, this->Kses, this->iv, dummy, dumy_len, GMAC);
        if (!check) {
            cout << "[ERROR] Error in checking server's busy peer response." << endl;
            return false;
        }
        cout<<BOLDRED;
        cout<<" You requested to play to a player not logged anymore."<<endl;
        cout<<" Refresh the list of logged users."<<endl;
        return true;
    }
    return false;
}
bool Client::handlePeerMsg(unsigned char *msg, size_t len) {

    if(extractMessageType(msg) == KEYEXCHRQST){
        free(this->t);
        this->t = nullptr;
        return handleKeyExchangeUserRequest(msg, len);

    }else if(extractMessageType(msg) == KEYEXCHRESP){
        bool check = handleKeyExchangeUserResponse(msg, len);
        if(check){
            play(false);
            applicant = false;
        }else{
        }
        if(!sendFreeStateToServer()){//FREE THE USER IN EACH CASE
            cout<<"[ERROR] Error set free state. "<<endl;
            return false;
        }
        return check;
    }else if(extractMessageType(msg) == KEYEXCHCONFIRM){
        bool check = handleKeyExchangeUserConfirmation(msg, len);
        if(check){
            play(true);

        }
        if(!sendFreeStateToServer()){// FREE THE USER IN EACH CASE
            cout<<"[ERROR] Error set free state. "<<endl;
            return false;
        }
        return check;
    }else{
        return false;
    }
}
int Client::extractMessageType(unsigned char *msg) {
    return msg[0];
}

void Client::deserializeListOfLoggedUsers(unsigned char *list, size_t list_len) {

    cout<<"----LIST OF LOGGED USERS----"<<endl;
    updatedListOfLoggedUsers.clear();
    int counter = 0;
    int max_num = list_len/ USERNAME_SIZE_MAX;
    while(counter < max_num){
        char username[USERNAME_SIZE_MAX];
        memcpy(username, &list[counter*USERNAME_SIZE_MAX], USERNAME_SIZE_MAX);
        cout<<counter + 1<<") "<<username;
        if(strcmp(username, this->username.c_str())== 0 ){
            cout<<"[YOU]";
        }
        cout<<endl;
        counter++;
        updatedListOfLoggedUsers.push_back(username);
    }
    cout<<"----------------------------"<<endl;

}

void Client::playRequest(string adv_name) {
    cout<<"["<<this->username<<"]"<<" SENDING PLAY REQUEST WITH "<<adv_name<<endl;
    size_t msg_len = 0;
    unsigned char* peer_name = (unsigned char*)malloc(USERNAME_SIZE_MAX);
    if(!peer_name){
        cout<<"[ERROR] MEM ALLOC."<<endl;
        exit(1);
    }
    memset(peer_name, 0, USERNAME_SIZE_MAX);
    memset(this->adv_username, 0, USERNAME_SIZE_MAX);
    strncpy(reinterpret_cast<char *>(peer_name), adv_name.c_str(), USERNAME_SIZE_MAX);
    strncpy(this->adv_username, adv_name.data(), USERNAME_SIZE_MAX);

    unsigned char* msg = this->servlet_.createAuthenticatedMsg(CHLRQST, this->username, this->Kses, this->iv, peer_name, USERNAME_SIZE_MAX, msg_len, GCM);
    if(!msg){
        cerr<<"[ERROR] Error creating msg"<<endl;
        return;
    }

    int ret = sendto(socket_, msg, msg_len, 0, (sockaddr*)&server_params, sizeof(server_params) );
    if(ret == -1){
        cerr<<"[ERROR] Error sending msg"<<endl;
    }
    free(msg);
    free(peer_name);
    cout<<"["<<this->username<<"]"<<" PLAY REQUEST SENT TO "<<adv_name<<endl;
    cout<<"["<<this->username<<"]"<<" WAITING FOR A RESPONSE"<<endl;
    applicant = true;
}

bool Client::handleUserListResponse(unsigned char *msg, size_t len) {
    unsigned char* list = nullptr; size_t list_len = 0;
    bool check = this->servlet_.checkAuthenticatedMsg(msg, len, this->Kses, this->iv, list, list_len, GCM);
    if(!check){
        cout<<"[ERROR] Error receiving User list Response."<<endl;
        return false;
    }
    deserializeListOfLoggedUsers(list, list_len);
    free(list);

    return true;
}

bool Client::handleChallengeRequest(unsigned char *msg, size_t len) {
    // HANDLE CHALLENG REQUEST FROM ANOTHER USER

    unsigned char* peer_name= nullptr; size_t peer_name_len = 0;
    bool check = this->servlet_.checkAuthenticatedMsg(msg, len, this->Kses, this->iv, peer_name, peer_name_len, GCM);
    if(!check){
        cout<<"[ERROR] Error in checking CHALLENGE REQUEST."<<endl;
        return false;
    }


    cout<<"-------------GAME REQUEST FROM "<<(const char*)peer_name<<"---------"<<endl;
    string res;
    bool accepted = false;
    while(1){
        cout<<"TYPE YES/NO"<<endl;
        cin>>res;
        if(!res.compare("YES")){
            accepted = true;
            strncpy(this->adv_username, reinterpret_cast<const char *>(peer_name), USERNAME_SIZE_MAX);
            break;
        }else if(!res.compare("NO")){
            accepted = false;
            break;
        }else{
            cout<<"Type a valid response"<<endl;
        }

    }
    size_t message_len = USERNAME_SIZE_MAX + MSGCODESIZE;
    unsigned char* message = (unsigned char*)malloc(message_len);
    if(!message){
        cout<<"[ERROR] MEM ALLOC."<<endl;
        exit(1);
    }
    memcpy(message,peer_name, USERNAME_SIZE_MAX);
    char v;
    if(accepted){
        v = ACCEPT;
    }else{
        v = REFUSE;
    }
    memcpy(&message[USERNAME_SIZE_MAX], &v, MSGCODESIZE);
    size_t response_len;
    unsigned char *response = this->servlet_.createAuthenticatedMsg(CHLRESP,"Server",this->Kses,this->iv,message, message_len, response_len,GCM);
    if(!response){
        cout<<"[ERROR] Error creating msg"<<endl;
    }
    int ret = sendto(this->socket_, response, response_len, 0,
                     (sockaddr *) &this->server_params, sizeof(this->server_params));
    if (ret == -1) {
        cerr << "[ERROR]Error sending msg" << strerror(errno)<<endl;
        return false;
    }
    return true;
}

bool Client::handleChallengeResponse(unsigned char *msg, size_t len) {
    unsigned char* response= nullptr; size_t response_len = 0;
    bool check = this->servlet_.checkAuthenticatedMsg(msg, len, this->Kses, this->iv, response, response_len, GCM);
    if(!check){
        cout<<"[ERROR] Error receiving Challenge response."<<endl;
        return false;
    }
    unsigned char* peer_name = (unsigned char*)malloc(USERNAME_SIZE_MAX);
    unsigned char* resp = (unsigned char*)malloc(MSGCODESIZE);
    if(!peer_name || !resp){
        cout<<"[ERROR] MEM ALLOC."<<endl;
        exit(1);
    }
    memcpy(peer_name, response, USERNAME_SIZE_MAX);
    memcpy(resp, &response[USERNAME_SIZE_MAX], MSGCODESIZE);
    free(response);
    if(!strcmp(reinterpret_cast<const char *>(peer_name), this->adv_username)){
        cout<<"[ERROR] Response from a wrong player."<<endl;
        return false;
    }
    if(*resp == ACCEPT){
        cout<<BOLDGREEN;
        cout<<" The player "<<this->adv_username<<" accepted your game request. :)"<<endl;
        cout<<" Waiting for his/her info from the Server..."<<endl;
        cout<<RESET<<endl;
    }else{
        cout<<BOLDRED;
        cout<<" The player "<<this->adv_username<<" refused your game request. :("<<endl;
        applicant = false;
        cout<<RESET<<endl;
    }
    free(resp);
    return true;
}

bool Client::handleChallengeInfo(unsigned char *msg, size_t len) {
    cout<<"["<<this->username<<"]"<<" Receiving peer info"<<endl;
    unsigned char* payload= nullptr; size_t payload_len = 0;
    bool check = this->servlet_.checkAuthenticatedMsg(msg, len, this->Kses, this->iv, payload, payload_len, GCM);
    if(!check){
        cout<<"[ERROR] Error receiving Challenge response."<<endl;
        return false;
    }
    char ip[INET_ADDRSTRLEN];
    memcpy(ip, payload,INET_ADDRSTRLEN );
    uint16_t port;
    memcpy(&port, &payload[INET_ADDRSTRLEN], sizeof(in_port_t));
    this->adv_params.sin_family = AF_INET;
    this->adv_params.sin_port = port;


    size_t peer_pub_key_len = payload_len - INET_ADDRSTRLEN - sizeof(in_port_t) - 8 ;
    unsigned char* peer_pub_key = (unsigned char* )malloc(peer_pub_key_len);
    if(peer_pub_key == nullptr){
        cout<<"[ERROR] MEM ALLOC."<<endl;
        exit(1);
    }
    memcpy(peer_pub_key, &payload[INET_ADDRSTRLEN + sizeof(in_port_t)],peer_pub_key_len );
    //BIO_dump_fp(stdout, (const char*)peer_pub_key, peer_pub_key_len);
    this->adv_pubkey = this->servlet_.deserializeKeys(peer_pub_key, peer_pub_key_len);
    inet_pton(AF_INET, ip, &(this->adv_params.sin_addr));
    free(peer_pub_key);
    free(payload);
    return true;
}

bool Client::handleKeyExchangeUserRequest(unsigned char *msg, size_t len) {
    cout<<BOLDYELLOW;
    unsigned char* id = extractIDFromMsg(msg);
    id[USERNAME_SIZE_MAX - 1] = '\0';

    cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] Key exchange auth. request from "<<id<<endl;
    this->adv_username[USERNAME_SIZE_MAX - 1] = '\0';
    if(0 != strncmp(reinterpret_cast<const char *>(id), this->adv_username, USERNAME_SIZE_MAX)){
        cout<<"[ERROR] Key exchange from an unexpected user."<<endl;
        free(id);
        return false;
    }

    bool ok = this->servlet_.checkHelloRequest(msg, len, this->adv_pubkey , this->adv_nonce);
    if (!ok) {
        cout<<"[PLAYER AUTH][ERROR] Error checking authentication request"<<id<<endl;
        free(id);
        return false;
    }
    cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] Player Authentication request is ok"<<endl;
    //SEND RESPONSE
    this->my_dh_game_session_keys = servlet_.generateNewDHKeys();
    if (!this->my_dh_game_session_keys) {
        cerr << "Error DH key's Generation" << endl;
        return false;
    }
    cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] Response Creation"<<endl;
    size_t response_len;
    unsigned char *response = this->servlet_.createHelloResponse(KEYEXCHRESP, this->username, nullptr,
                                                                  this->prvkey,  this->my_nonce, this->adv_nonce, this->my_dh_game_session_keys,
                                                                  response_len);
    if(!response){
        cout<<"[ERROR] Error creating msg"<<endl;
    }
    int ret = sendto(this->adv_socket, response, response_len, 0,
                     (sockaddr *) &this->adv_params, sizeof(this->adv_params));
    if (ret == -1) {
        cerr << "[ERROR] Error sending msg" << strerror(errno)<<endl;
        return false;
    }
    free(response);
    cout<<RESET<<endl;
    return true;
}
unsigned char* Client::extractIDFromMsg(unsigned char* msg){
    unsigned char* ID = (unsigned char*)malloc(USERNAME_SIZE_MAX);
    if(ID == nullptr){
        cout<<"[ERROR] MEM ALLOC"<<endl;
        exit(1);
    }
    memset(ID, 0, USERNAME_SIZE_MAX);
    memcpy(ID, &msg[MSGCODESIZE],  USERNAME_SIZE_MAX);
    return ID;

}

bool Client::handleKeyExchangeUserResponse(unsigned char *msg, size_t len) {
    cout<<BOLDYELLOW;
    bool ok = servlet_.checkHelloResponse(msg, len, nullptr, this->adv_pubkey, this->adv_dh_game_session_pub_key, this->my_nonce, this->adv_nonce);
    if(!ok){
        cout<<"Error checking Hello Response"<<endl;
        return false;

    }
    cout<<"["<<this->username<<"]"<<" Key Exchange Response is ok."<<endl;

    /*-------------------------------- SENDING ACCEPTATION --------------------------------------------------*/
    cout<<"["<<this->username<<"]"<<" Sending Key Exchange Confirmation"<<endl;
    /* CREATE DH KEYS   */
    this->my_dh_game_session_keys = servlet_.generateNewDHKeys();
    if(!this->my_dh_game_session_keys){
        cout<<"[ERROR] Error Generating DH key"<<endl;
        return false;
    }
    //DERIVE SHARED SECRET
    this->game_key = this->servlet_.deriveSecretDH(this->my_dh_game_session_keys, this->adv_dh_game_session_pub_key, this->game_key_len);
    if(!this->game_key){
        cout<<"[ERROR] Error derivation DH shared key with server."<<endl;
        return false;
    }
    msg = this->servlet_.createHelloAcceptance(KEYEXCHCONFIRM, this->username, this->prvkey, this->my_dh_game_session_keys, this->adv_nonce, len );
    if(!msg){
        cout<<"[ERROR] Error creating Hello acceptance msg"<<endl;
    }

    int ret = sendto(this->adv_socket, msg, len, 0, (sockaddr*)&this->adv_params, sizeof(this->adv_params) );
    if(ret == -1){
        cerr<<"[ERROR] Error sending msg"<<endl;
        return false;
    }

    return true;
}

bool Client::handleKeyExchangeUserConfirmation(unsigned char *msg, size_t len) {
    cout<<BOLDYELLOW;
    cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] Checking Key Exchange Confirmation"<<endl;
    bool ok = this->servlet_.checkHelloAcceptance(msg, len, this->adv_pubkey, this->adv_dh_game_session_pub_key, this->my_nonce);
    if (!ok) {
        cerr << "[ERROR]Error in checking Hello Accept message" << endl;
        return false;
    }
    cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] Creating session key."<<endl;
    //BIO_dump_fp(stdout, (const char*)client->dh_connectionKeyPair, sizeof(client->dh_connectionKeyPair));

    this->game_key = this->servlet_.deriveSecretDH( this->my_dh_game_session_keys, this->adv_dh_game_session_pub_key, this->game_key_len);
    if(!this->game_key){
        cerr << "[ERROR] Error creating session key" << endl;
        return false;
    }
    unsigned char* peer_name = extractIDFromMsg(msg);
    cout<<"["<<this->username<<"]"<<"[PLAYER AUTH] KEY EXCHANGE ACCOMPLISHED with"<<peer_name<<endl;
    free(peer_name);


    return true;
}

bool Client::sendFreeStateToServer() {
    //SENDING BUSY IN GAME STATE TO SERVER
    cout<<"["<<this->username<<"]"<<" Sending free state to server"<<endl;
    size_t msg_free_len;
    unsigned char* msg_free = servlet_.createAuthenticatedMsg(FREESTATE, this->username, this->Kses, this->iv,
                                                              nullptr, 0, msg_free_len, GMAC );

    int ret = sendto(socket_, msg_free, msg_free_len,0,
                     (sockaddr *) &this->server_params, sizeof(this->server_params));
    if(ret == -1){
        cout<<"[ERROR] Error sending free state to server"<<endl;
    }
    free(msg_free);

    return true;
}
