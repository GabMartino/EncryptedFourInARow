//
// Created by gabriele on 16/01/21.
//

#include "Server.hpp"

/**
 * This method start the server
 *
 *
 */

SecureConnectionServlet Server::servlet_;
void Server::start() {
    //------------------INITIALIZATION OF THE NETWORK PARAMETERS
    int master_sk;
    int optval;
    int ret;
    int client_socket[MAX_NUMBER_OF_CLIENTS];

    for(unsigned int i = 0; i<MAX_NUMBER_OF_CLIENTS; i++){
        client_socket[i] = 0;
    }

    /* New socket creation */
    master_sk = socket(AF_INET, SOCK_STREAM, 0);
    if(master_sk <= 0) {
        cerr<<"[SERVER][ERROR]Error creating new socket"<<endl;
        return;
    }

    optval = 1;
    ret = setsockopt(master_sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if(ret == -1) {
        cerr<<"[SERVER][ERROR]Error setting SO_REUSEADDR"<<endl;
        exit(1);
    }
    this->srv_addr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(master_sk, (sockaddr*)&this->srv_addr,sizeof(this->srv_addr));
    if(ret == -1){
        cout<<"[SERVER][ERROR]Error binding the Socket"<<endl;
        exit(1);
    }

    /* Creating backlog queue */
    ret = listen(master_sk, BACKLOG_SIZE);
    if(ret == -1) {
        cout<<"[SERVER][ERROR]Error creating backlog queue, size"<<BACKLOG_SIZE<<endl;
        exit(1);
    }

    socklen_t cl_len;
    char cl_paddr[INET_ADDRSTRLEN];
    fd_set readfds;
    int max_sd;
    int activity;

    //Create a list of waiting connection
    vector<WaitingClientConnection> waitingConnections;


    printCommands();
    while(1) {
        cout<<BOLDCYAN;
        cout<<endl;
        cout<<"SERVER>>";
        cout.flush();

        //-----------------------RESET THE LISTENING SOCKETS
        FD_ZERO(&readfds);//clear the socket set
        FD_SET(master_sk, &readfds);//insert the master socket in the set
        FD_SET(STDIN_FILENO, &readfds);//insert the std input in the socket set to read from keyboard eventual command
        max_sd = master_sk;
        //INSERT IN THE SET THE EVENTUAL NEW CLIENTS CONNECTED
        for(unsigned int i = 0; i< MAX_NUMBER_OF_CLIENTS;i++){
            if(client_socket[i]>0){
                //cout<<"[SERVER] Insert socket"<<client_socket[i]<<" in socket listening list"<<endl;
                FD_SET(client_socket[i], &readfds);
                if(client_socket[i]>max_sd){
                    max_sd = client_socket[i];
                }
            }
        }
        //cout<<"[SERVER] Server is listening..."<<endl;
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);//wait for a new incoming connection
        if(activity < 0 and errno != EINTR){
            cerr<<"Select error"<<strerror(errno)<<endl;
            return;

        }
        //------------------------A SOCKET HAS BEEN ACTIVATED

        //CHECK WHICH SOCKET HAS BEEN ACTIVATED
        if(FD_ISSET(master_sk, &readfds)){
            cout<<endl;
            //------------MASTER SOCKET ACTIVATED -> A CLIENT WANT TO LOGIN------------
            cout <<BOLDYELLOW<<endl;
            cout<<"[SERVER] HANDLING NEW INCOMING CONNECTION"<<endl;
            WaitingClientConnection newClient;

            /* Accepting a request arrived at sk, which will be served by cl_sk */
            cl_len = sizeof(newClient.addr);
            newClient.client_socket = accept(master_sk, (sockaddr*)&newClient.addr, &cl_len);
            if(newClient.client_socket == -1) {
                cout<<"[SERVER] Error during the connection"<<endl;
                return;
            }
            //Print client info
            inet_ntop(AF_INET, &newClient.addr.sin_addr, cl_paddr, sizeof(cl_paddr));
            int tmp_cl_port = ntohs(newClient.addr.sin_port);
            cout<<"[SERVER] Connection established with client "<<inet_ntoa(newClient.addr.sin_addr) <<", port: "<<tmp_cl_port<<endl;

            //insert the new socket to the array of socket to check
            for(unsigned int i = 0; i< MAX_NUMBER_OF_CLIENTS; i++){
                if(client_socket[i] == 0){//Empty space
                    cout<<"[SERVER] Insert new socket in the socket list"<<endl;
                    client_socket[i] = newClient.client_socket;
                    break;
                }
            }
            cout<<"[SERVER] Inserting the connected user in the waiting list..."<<endl;
            waitingConnections.push_back(newClient);
            cout<<"[SERVER] Waiting list size: "<<waitingConnections.size()<<endl;
            cout <<"\033[0m\n";
            /**
             * Since I can accept authentication only from users already registered ( of which I have
             * public keys), I prepare the net parameters of this new request and then set them in the
             * waitingConnections list. Later I'll check the request of authentication.
             *
             */

        }else if(FD_ISSET(STDIN_FILENO, &readfds)){//INCOMING COMMAND FROM STDIN
            //-----------CHECK THE TERMINAL COMMAND
            string c;
            cin>>c;
            if(!cin){
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                continue;
            }
            checkCommand(c);
            cin.clear();
        }else {
            cout<<endl;
            //--------------- NEW MESSAGE FROM A CONNECTED USERS
            //Check other eventual activated sockets
            for (unsigned int i = 0; i < MAX_NUMBER_OF_CLIENTS; i++) {
                if (client_socket[i] > 0 and FD_ISSET(client_socket[i], &readfds)) {
                    //cout <<"[SERVER] Check new incoming requests..." << endl;
                    /**
                     * TAKE THE USER:
                     * if he/she is in the waiting list means that it's still unidentified, so it should be identified
                     * with first validated message. Otherwise his/her socket is already registered in his struct
                     *
                     */
                    User* client = nullptr;
                    User tmpUser;
                    bool fromWaitinglist = false;
                    int activatedSocketIndex = searchNewClientInWaitingListBySocketNumber(waitingConnections,
                                                                                          client_socket[i]);
                    if(activatedSocketIndex != -1){
                        tmpUser.client_socket = client_socket[i];
                        tmpUser.addr = waitingConnections.at(activatedSocketIndex).addr;
                        fromWaitinglist = true;
                    }else{
                        client = searchConnectedClientBySocketNumber(client_socket[i]);
                        if (!client) {
                            cout << "[SERVER][ERROR] Error Client not found" << endl;
                            break;
                        }
                        tmpUser.client_socket = client->client_socket;
                        tmpUser.addr = client->addr;
                    }

                    // RECEIVE MESSAGE
                    unsigned char received_msg[BUFF_MAX_SIZE];
                    memset(received_msg, 0, BUFF_MAX_SIZE);

                    socklen_t cli_addr_size = sizeof(tmpUser.addr);
                    int ret = recvfrom(client_socket[i], received_msg, BUFF_MAX_SIZE, 0,(sockaddr *) &tmpUser.addr, &cli_addr_size);
                    if(ret == -1 || ret == 0){
                        if(ret == -1){
                            cerr<<"[SERVER][ERROR] Error Receiving Data"<<strerror(errno)<<endl;
                        }else{
                            cout<<"[SERVER][ERROR] Closing socket"<<endl;
                        }
                        FD_CLR(client_socket[i], &readfds);
                        close(client_socket[i]);
                        client_socket[i] = 0;
                        if(fromWaitinglist){
                            waitingConnections.erase(waitingConnections.begin() + activatedSocketIndex);//delete the list of unknown connection
                        }else{
                            try{
                                client->client_socket = 0;
                                client->iv = nullptr;
                                free(client->Kses);
                                free(client->nonce_client);
                                free(client->nonce_server);
                                EVP_PKEY_free(client->dh_pubkey);
                                EVP_PKEY_free(client->dh_connectionKeyPair);
                                EVP_PKEY_free(client->pubK);
                                client->logged = false;
                                client->inGame = false;
                            }catch (exception &e){
                                cerr<<e.what()<<endl;
                            }

                        }
                    }
                    if(fromWaitinglist){//actually this is always true in the hello request
                        unsigned char *ID = extractIDFromMsg(received_msg);
                        string Username(reinterpret_cast<char *>(ID));
                        client = searchConnectedClientByUsername(Username);
                        bool error = false;
                        if (!client) {
                            cerr << "[SERVER][ERROR]Hello message error: User not registered" << endl;
                            error = true;
                        }else if(client->logged){
                            cerr<< "[SERVER][ERROR] A user is trying to authenticated as an already logged user."<<endl;
                            error = true;
                        }else{
                            client->addr = tmpUser.addr;
                            client->client_socket = tmpUser.client_socket;
                        }
                        waitingConnections.erase(waitingConnections.begin() +
                                                 activatedSocketIndex);//delete the list of unknown connection
                        if(error)
                            continue;

                    }

                    /* HANDLE HELLO REQUESTS */
                    bool ok = handleMessages(received_msg, ret, client);
                    if(!ok){
                        cout<<"[SERVER][ERROR] Error handling received msg."<<endl;
                        if(fromWaitinglist){
                            /**
                             * If from waiting list was the first message that could have been forged
                             * so clear the info
                             */
                            client->client_socket = 0;
                        }
                    }
                }

            }
        }
    }
    return;
}
/**
 * This method returns the value in the first byte, this assume that the header of the msg is of one byte
 *
 * @param msg
 * @return
 */
int Server::extractMessageType(unsigned char *msg) {
    return msg[0];

}
/**
 * This method returns the ID from a message, considering the it is just after the HEADER of MSGCODESIZE bytes
 * @param msg
 * @return
 */

unsigned char* Server::extractIDFromMsg(unsigned char* msg){
    unsigned char* ID = (unsigned char*)malloc(USERNAME_SIZE_MAX);
    if(!ID){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(ID, &msg[MSGCODESIZE],  USERNAME_SIZE_MAX);
    return ID;

}
/**
 * This methods deserialize and check all the messages.
 *
 *
 * @param received_msg
 * @param msg_len
 * @param client: struct that represent the sender of the message
 * @return
 */
bool Server::handleMessages(unsigned char *received_msg, size_t msg_len, User* client) {

    if (extractMessageType(received_msg) == HELLORQST) {
        cout << "\033[1;35m";
        cout<<"[SERVER] AUTHENTICATION with "<<client->Username<<endl;
        /* -------------------------------- RECEIVE HELLO RQST -----------------------------------*/
        if(client->logged){
            cout<<"[SERVER][ERROR] Repeating Authentication attempt."<<endl;
            return false;
        }
        if(nullptr == ( client->pubK = fetchPublicKey(client->PublicKeyPath))){
            cerr<<"[SERVER][ERROR] Error retrieving user public key "<<endl;
            return false;
        }//Extract the public key of the client
        cout<<"[SERVER][AUTH] Checking HELLO REQUEST"<<endl;
        bool ok;
        ok = this->servlet_.checkHelloRequest(received_msg, msg_len, client->pubK , client->nonce_client);
        if (!ok) {
            cerr << "[SERVER][ERROR] Error in checking Hello Message" << endl;
            if(client->nonce_client != nullptr){//Send hello refuse
                size_t refuse_len;
                unsigned char* refuse = servlet_.createHelloRefuse(HELLOREFUSE, "Server",client->nonce_client, this->cert, this->prvkey, refuse_len);
                if(!refuse){
                    cout<<"[SERVER][ERROR] Error creating msg"<<endl;
                }
                int ret = sendto(client->client_socket, refuse, refuse_len, 0,
                                 (sockaddr *) &client->addr, sizeof(client->addr));
                if (ret == -1) {
                    cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
                    return false;
                }
                free(refuse);
            }
            return false;
        }
        cout<<"[SERVER][AUTH] HELLO REQUEST IS OK."<<endl;
        /* -------------------------- SEND HELLO RESPONSE --------------------------------------*/
        client->dh_connectionKeyPair = servlet_.generateNewDHKeys();

        if (!client->dh_connectionKeyPair) {
            cerr << "Error DH key's Generation" << endl;
            return false;
        }
        cout << "[SERVER][AUTH] Sending HELLO RESPONSE" << endl;
        size_t response_len;
        unsigned char *response = this->servlet_.createHelloResponse(HELLORESP, "Server", this->cert,
                                                                      this->prvkey,  client->nonce_server, client->nonce_client, client->dh_connectionKeyPair,
                                                                      response_len);
        if(!response){
            cout<<"[SERVER][ERROR] Error creating msg"<<endl;
        }
        int ret = sendto(client->client_socket, response, response_len, 0,
                         (sockaddr *) &client->addr, sizeof(client->addr));
        if (ret == -1) {
            cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
            return false;
        }
        free(response);
        cout <<"\033[0m\n";

    }else if(extractMessageType(received_msg) == HELLOACCEPT){
        cout << "\033[1;35m";
        cout<<"[SERVER][AUTH] Checking HELLO ACCEPT"<<endl;
        bool ok;
        ok = this->servlet_.checkHelloAcceptance(received_msg, msg_len, client->pubK, client->dh_pubkey, client->nonce_server);
        if (!ok) {
            cerr << "[SERVER][ERROR]Error in checking Hello Accept message" << endl;
            if(client->nonce_client != nullptr){//Send hello refuse
                size_t refuse_len;
                unsigned char* refuse = servlet_.createHelloRefuse(HELLOREFUSE, "Server",client->nonce_client, this->cert, this->prvkey, refuse_len);
                if(!refuse){
                    cout<<"[SERVER][ERROR] Error creating msg"<<endl;
                }
                int ret = sendto(client->client_socket, refuse, refuse_len, 0,
                                 (sockaddr *) &client->addr, sizeof(client->addr));
                if (ret == -1) {
                    cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
                    return false;
                }
                free(refuse);
            }




            return false;
        }
        cout<<"[SERVER][AUTH] Creating session key."<<endl;
        //BIO_dump_fp(stdout, (const char*)client->dh_connectionKeyPair, sizeof(client->dh_connectionKeyPair));

        client->Kses = this->servlet_.deriveSecretDH( client->dh_connectionKeyPair, client->dh_pubkey, client->Kses_len);
        if(!client->Kses){
            cerr << "[SERVER][ERROR] Error creating session key" << endl;
            return false;
        }
        cout<<"[SERVER][AUTH] USER "<<client->Username<<" IS AUTHENTICATED."<<endl;
        client->logged = true;
        cout <<"\033[0m\n";
    }else if(extractMessageType(received_msg) == PORTINFO){
        cout << "\033[1;33m";
        cout<<"[SERVER][AUTH] Receiving OnList port info from "<<client->Username<<endl;
        bool ok;
        unsigned char* port = nullptr; size_t port_len = 0;
        ok = this->servlet_.checkAuthenticatedMsg(received_msg, msg_len, client->Kses, client->iv,port, port_len, GCM);
        if(!ok){
            cout << "[SERVER][ERROR] Error checking authenticated msg" << endl;
            return false;
        }
        uint16_t portString;
        memcpy(&portString, port, port_len);
        client->onListenPort = portString;
        free(port);
        cout <<"\033[0m\n";
    }else if(extractMessageType(received_msg) == USERLISTRQST){
        cout << "\033[1;36m";
        cout<<"[SERVER][CLIENT] User list request from "<<client->Username<<endl;
        bool ok;
        unsigned char* dummy = nullptr; size_t dummy_len = 0;
        ok = this->servlet_.checkAuthenticatedMsg(received_msg, msg_len, client->Kses, client->iv,dummy, dummy_len, GMAC);
        if(!ok){
            return false;
        }
        size_t list_len;
        unsigned char* list = serializeListOfLoggedUsers(list_len);
        if(!list){
            cout<<"Error list retrieving"<<endl;
            return false;
        }
        size_t response_len;
        unsigned char *response = this->servlet_.createAuthenticatedMsg(USERLISTRESP,"Server",client->Kses,client->iv,list, list_len, response_len,GCM);
        if(!response){
            cout<<"[SERVER][ERROR] Error creating msg"<<endl;
        }
        int ret = sendto(client->client_socket, response, response_len, 0,
                         (sockaddr *) &client->addr, sizeof(client->addr));
        if (ret == -1) {
            cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
            return false;
        }
        free(response);

        cout<<"[SERVER][CLIENT] Send User list."<<endl;

        cout <<RESET<<endl;
    }else if(extractMessageType(received_msg) == CHLRQST){
        cout<<BOLDBLUE;
        cout<<"[SERVER][CLIENT] "<<client->Username<<" requests to play..."<<endl;
        //CHECK THE VALIDITY OF THE CHALLENGE REQUEST
        unsigned char* peer_name = nullptr; size_t peer_name_len = 0;
        bool ok = this->servlet_.checkAuthenticatedMsg(received_msg, msg_len, client->Kses, client->iv,peer_name, peer_name_len, GCM);
        if(!ok){
            cout<<"[SERVER][CLIENT][ERROR] Error checking msg"<<endl;
            return false;
        }
        //Extract the peer name if exist
        User* peer = searchConnectedClientByUsername( (string)reinterpret_cast<char*>(peer_name));
        if(!peer){
            cout<<"[SERVER][CLIENT] User not found"<<endl;
            return false;
        }
        if(peer->logged){
            if(!peer->inGame){//IF THE PEER IS FREE
                unsigned char* peer_requirer = (unsigned char*)malloc(USERNAME_SIZE_MAX);
                if(!peer_requirer){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
                memset(peer_requirer, 0, USERNAME_SIZE_MAX);
                strcpy(reinterpret_cast<char *>(peer_requirer), client->Username.c_str());

                //CREATE A NEW MESSAGE FOR THE OTHER PLAYER
                size_t response_len;
                unsigned char *response = this->servlet_.createAuthenticatedMsg(CHLRQST,"Server",peer->Kses,peer->iv,peer_requirer, USERNAME_SIZE_MAX, response_len,GCM);
                if(!response){
                    cout<<"[SERVER][ERROR] Error creating msg"<<endl;
                }
                //FORWARD THE REQUEST TO THE OTHER PLAYER
                int ret = sendto(peer->client_socket, response, response_len, 0,
                                 (sockaddr *) &peer->addr, sizeof(peer->addr));
                if (ret == -1) {
                    cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
                    return false;
                }
                free(response);
                cout<<"[SERVER][CLIENT] "<<client->Username<<"'s request forwarded to"<<peer_name<<endl;
                free(peer_requirer);
                client->inGame = true; //set a busy state to avoid concurrent requests
                peer->inGame = true;
            }else{
                size_t response_len;
                unsigned char *response = this->servlet_.createAuthenticatedMsg(BUSYPEER,"Server",client->Kses,client->iv,
                                                                                 nullptr, 0, response_len,GMAC);
                if(!response){
                    cout<<"[SERVER][ERROR] Error creating msg"<<endl;
                }
                //FORWARD THE REQUEST TO THE OTHER PLAYER
                int ret = sendto(client->client_socket, response, response_len, 0,
                                 (sockaddr *) &client->addr, sizeof(client->addr));
                if (ret == -1) {
                    cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
                    return false;
                }
                free(response);
                cout<<"[SERVER][CLIENT] "<<client->Username<<"'s play request to a busy peer"<<endl;

            }
        }else{//the peer who the client want to request to play is not logged anymore
            size_t response_len;
            unsigned char *response = this->servlet_.createAuthenticatedMsg(NOTLOGGEDPEER,"Server",client->Kses,client->iv,
                                                                             nullptr, 0, response_len,GMAC);
            if(!response){
                cout<<"[SERVER][ERROR] Error creating msg"<<endl;
            }
            //FORWARD THE REQUEST TO THE OTHER PLAYER
            int ret = sendto(client->client_socket, response, response_len, 0,
                             (sockaddr *) &client->addr, sizeof(client->addr));
            if (ret == -1) {
                cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
                return false;
            }
            free(response);
            cout<<"[SERVER][CLIENT] "<<client->Username<<"'s response for a logged out user's challenge request"<<peer_name<<endl;
        }

        free(peer_name);
        cout<<RESET<<endl;
    }else if(extractMessageType(received_msg) == CHLRESP){
        cout<<BOLDBLUE;
        cout<<"[SERVER][CLIENT]"<<client->Username<<" responses to a challenge."<<endl;
        bool ok;
        unsigned char* response = nullptr; size_t response_len = 0;
        ok = this->servlet_.checkAuthenticatedMsg(received_msg, msg_len, client->Kses, client->iv,response, response_len, GCM);
        if(!ok){
            cout<<"[SERVER][CLIENT][ERROR] Error checking msg"<<endl;
            return false;
        }
        unsigned char* peer_name = (unsigned char*)malloc(USERNAME_SIZE_MAX);
        if(!peer_name){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
        unsigned char* resp = (unsigned char*)malloc(MSGCODESIZE);
        if(!resp){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
        memcpy(peer_name, response, USERNAME_SIZE_MAX);
        memcpy(resp, &response[USERNAME_SIZE_MAX], MSGCODESIZE);

        User* peer = searchConnectedClientByUsername( (string)reinterpret_cast<char*>(peer_name));
        if(!peer){
            cout<<"[SERVER][CLIENT] User not found"<<endl;
            return false;
        }
        unsigned char* peer_requirer_name= (unsigned char*)malloc(USERNAME_SIZE_MAX);
        if(!peer_requirer_name){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
        memset(peer_requirer_name, 0, USERNAME_SIZE_MAX);
        strcpy(reinterpret_cast<char *>(peer_requirer_name), peer->Username.c_str());


        unsigned char* response_forward = (unsigned char*)malloc(USERNAME_SIZE_MAX +MSGCODESIZE );
        if(!response_forward){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
        memcpy(response_forward, peer_requirer_name, USERNAME_SIZE_MAX);
        memcpy(&response_forward[USERNAME_SIZE_MAX], resp, MSGCODESIZE);
        cout<<"[SERVER] Sending response to "<<peer->Username<<endl;
        size_t response_msg_len;
        unsigned char *response_msg = this->servlet_.createAuthenticatedMsg(CHLRESP,"Server",peer->Kses,peer->iv,response_forward, USERNAME_SIZE_MAX +MSGCODESIZE, response_msg_len,GCM);
        if(!response){
            cout<<"[SERVER][ERROR] Error creating msg"<<endl;
        }
        int ret = sendto(peer->client_socket, response_msg, response_msg_len, 0,
                         (sockaddr *) &peer->addr, sizeof(peer->addr));
        if (ret == -1) {
            cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
            return false;
        }
        free(response);
        free(peer_name);
        free(response_forward);
        free(response_msg);
        //CREATE AN INFO
        if(*resp == ACCEPT){

            size_t msg_len;
            cout<<"[SERVER] Sending mutual information to the two peers."<<endl;
            unsigned char* msg = this->createChallengeInfoMsg(peer, client, msg_len);
            if(!msg){
                cout<<"[SERVER][ERROR] Error creating msg"<<endl;
            }
            ret = sendto(peer->client_socket, msg, msg_len, 0,
                         (sockaddr *) &peer->addr, sizeof(peer->addr));
            if (ret == -1) {
                cerr << "[SERVER][ERROR]Error sending msg"  << strerror(errno)<<endl;
                return false;
            }
            free(msg);

            msg = this->createChallengeInfoMsg(client, peer, msg_len);
            if(!msg){
                cout<<"[SERVER][ERROR] Error creating msg"<<endl;
            }
            ret = sendto(client->client_socket, msg, msg_len, 0,
                         (sockaddr *) &client->addr, sizeof(client->addr));
            if (ret == -1) {
                cerr << "[SERVER][ERROR]Error sending msg" << strerror(errno)<<endl;
                return false;
            }
            free(msg);
        }else{
            client->inGame = false;
            peer->inGame = false;
        }
        free(resp);
        cout <<"\033[0m\n";
    }else if(extractMessageType(received_msg) == FREESTATE){
        cout << "\033[1m\033[34m";
        cout<<"[SERVER][CLIENT]"<<client->Username<<" FREED STATE"<<endl;
        bool ok;
        unsigned char* dummy = nullptr; size_t dummy_len = 0;
        ok = this->servlet_.checkAuthenticatedMsg(received_msg, msg_len, client->Kses, client->iv,dummy, dummy_len, GMAC);
        if(!ok){
            cout<<"[SERVER][CLIENT][ERROR] Error checking msg"<<endl;
            return false;
        }

        client->inGame = false;
        cout <<"\033[0m\n";

    }else if(extractMessageType(received_msg) == HELLOREFUSE){
        bool check = servlet_.checkHelloRefuse(received_msg, msg_len, nullptr, client->pubK, client->nonce_server);
        if(!check){
            cout<<"[ERROR] Hello Refuse message not valid, possible MIM."<<endl;
        }else{
            cout<<"[ERROR] Hello request not accepted from the server. Check the configuration"<<endl;
            exit(1);
        }


    }

    return true;


}

unsigned char *Server::createChallengeInfoMsg(User *to, User *peer, size_t& msg_len) {
    unsigned char* dest_peer_ip = (unsigned char*)malloc(INET_ADDRSTRLEN);
    if(!dest_peer_ip){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    inet_ntop(AF_INET, &peer->addr.sin_addr, reinterpret_cast<char *>(dest_peer_ip), INET_ADDRSTRLEN);
    size_t dest_peer_pub_key_len;
    unsigned char* dest_peer_pub_key = this->servlet_.serializeKeys(peer->pubK, dest_peer_pub_key_len);

    unsigned char* random_value = this->servlet_.createRandomValue(8);
    size_t payload_len = INET_ADDRSTRLEN + sizeof(in_port_t) + dest_peer_pub_key_len + 8;
    unsigned char* payload = (unsigned char*)malloc(payload_len);
    if(!payload){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}

    memcpy(payload, dest_peer_ip, INET_ADDRSTRLEN);
    //uint16_t port = htons(peer->addr.sin_port);
    memcpy(&payload[INET_ADDRSTRLEN],  &peer->onListenPort,sizeof(in_port_t) );
    memcpy(&payload[INET_ADDRSTRLEN + sizeof(in_port_t) ],dest_peer_pub_key,dest_peer_pub_key_len);


    unsigned char* msg = this->servlet_.createAuthenticatedMsg(CHLINFO, "SERVER", to->Kses, to->iv,payload, payload_len, msg_len, GCM);
    free(random_value);
    free(dest_peer_ip);
    free(dest_peer_pub_key);
    free(payload);

    return msg;
}
