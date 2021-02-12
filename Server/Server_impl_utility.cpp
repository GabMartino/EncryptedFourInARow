//
// Created by gabriele on 25/01/21.
//
#include "Server.hpp"


/**
 * *************************************************************************************
 *
 *                           UTILITIES TO INITIALIZE THE SERVER
 *
 * *************************************************************************************
 */


/**
 * This method fetch from an XML file the information of the users already registered:
 * ->Username
 * ->Public Key path
 * SEE THE DOC. TO VISUALIZE THE FORMAT OF THE XML FILE.
 * XML SCHEME CHECK NOT IMPLEMENTED
 *
 */
void Server::fetchUsersFromFile() {
    cout<<"[SERVER] ";
    cout<<"RETRIEVE USERS INFO FROM DB."<<endl;
    xml_document<> doc;
    xml_node<> * root_node = NULL;
    // Read the sample.xml file
    try{
        ifstream theFile (this->DB_file_path);
        vector<char> buffer((istreambuf_iterator<char>(theFile)), istreambuf_iterator<char>());
        buffer.push_back('\0');
        // Parse the buffer
        doc.parse<0>(&buffer[0]);
        // Find out the root node
        root_node = doc.first_node("DB_USERS");
        if(!root_node){
            cerr<<"Error reading root node. Check the XML file."<<endl;
            exit(1);
        }
        xml_node<>* user_node= root_node->first_node("User");
        if(!user_node){
            cerr<<"Error reading the first User node. Check the XML file."<<endl;
        }
        User* user;

        while(user_node){
            if(user and user->next == nullptr){
                user->next = new User();
                user = user->next;
            }

            if(listOfUsers == nullptr){
                user = new User();
                listOfUsers = user;
            }
            user->Username = (string)(user_node->first_node("Name")->value());
            if(user->Username.empty()){
                cerr<<"Username is empty. Check the XML file."<<endl;
            }
            user->PublicKeyPath = (string)(user_node->first_node("Public_key_path")->value());
            if(user->PublicKeyPath.empty()){
                cerr<<"Publick key path is empty. Check the XML file."<<endl;
            }
            user_node = user_node->next_sibling();
        }

        theFile.close();
    }catch(exception e){
        cout<<e.what()<<endl;
    }

    cout<<"[SERVER] USERS INFO RETRIEVED."<<endl;
}
/**
 * This method fetch the server's certificate from a file.
 * The path is given in the constructor.
 *
 */
void Server::fetchCertificateFromFile() {
    cout<<"[SERVER] ";
    cout<<"Reading Server's Certificate..."<<endl;
    FILE* file = fopen(this->Certificate_path.c_str(), "r");
    if(!file){
        cout<<"[ERROR] ERROR READING FILE."<<endl;
        cout<<"[ERROR]Closing..."<<endl;
        exit(1);
    }
    this->cert = PEM_read_X509(file, NULL, NULL, NULL);
    if(!this->cert){
        ERR_print_errors_fp(stderr);
        cout<<"[ERROR] ERROR READING CERTIFICATE FILE."<<endl;
        cout<<"[ERROR]Closing..."<<endl;
        exit(1);
    }
    fclose(file);
}
/**
 * This method will fetch the server's private key.
 * The file path is given in the constructor.
 *
 */
void Server::fetchPrivateKeyFromFile() {
    cout<<"[SERVER] ";
    cout<<"Reading Server's Private Key"<<endl;
    FILE* file = fopen(this->PrivateKey_path.c_str(), "r");
    if(!file){
        cout<<"[ERROR] ERROR READING FILE."<<endl;
        cout<<"[ERROR] Closing..."<<endl;
        exit(1);
    }

    this->prvkey = PEM_read_PrivateKey(file,NULL, NULL, NULL);
    if(!this->prvkey){
        ERR_print_errors_fp(stderr);
        cout<<"[ERROR] ERROR READING PRIVATE KEY FILE."<<endl;
        cout<<"[ERROR] Closing..."<<endl;
        exit(1);
    }
    fclose(file);
    cout<<"[SERVER] ";
    cout<<"Server's Private Key read with success."<<endl;
}
void Server::fetchAndSetNetParams() {
    cout<<"[SERVER] Fetch and Set Networking Server's Parameters"<<endl;
    xml_document<> doc;
    xml_node<> * root_node = NULL;
    // Read the sample.xml file
    ifstream theFile (this->netParams_path);
    vector<char> buffer((istreambuf_iterator<char>(theFile)), istreambuf_iterator<char>());
    buffer.push_back('\0');

    // Parse the buffer
    doc.parse<0>(&buffer[0]);
    // Find out the root node
    root_node = doc.first_node("SERVER_PARAMS");
    if(!root_node){
        cerr<<"[SERVER][ERROR]Error reading root node"<<endl;
        exit(1);
    }
    string ip = (string)(root_node->first_node("IP_ADDRESS")->value());
    if(ip.empty()){
        cerr<<"[SERVER][ERROR] IP VALUE FIELD EMPTY."<<endl;
        exit(1);
    }
    memset(&this->srv_addr, 0, sizeof(srv_addr));
    int ret = inet_pton(AF_INET, ip.c_str(), &this->srv_addr.sin_addr);
    if(ret <= 0){
        cerr<<"[SERVER][ERROR]ERROR PARSING SERVER IP ADDRESS"<<endl;
        exit(1);
    }
    int port = atoi(root_node->first_node("PORT")->value());
    if(port <= 0 || port > 65535){
        cerr<<"[SERVER][ERROR]ERROR PARSING SERVER PORT"<<endl;
        exit(1);
    }
    this->srv_addr.sin_family = AF_INET;
    this->srv_addr.sin_port = htons(port);
    printServerNetworkParams();
    theFile.close();
}
/**
 * **********************************************************************
 *
 *                      PRINT FUNCTIONS
 *
 ************************************************************************
 */


/**
 * This method will print the clients that are now connected to the server
 *
 */
void Server::printListofLoggedUsers() {
    cout<<BOLDBLUE;
    User* p = listOfUsers;
    cout<<"[SERVER] LIST OF LOGGED USERS"<<endl;
    int counter = 1;
    bool noUsers = true;
    while(p and p->logged){
        cout<<BOLDBLUE;
        noUsers = false;
        if(p->logged){
            cout<<counter<<") Username: "<<p->Username<<endl;
            cout<<"   inGame: ";
            if(p->inGame){
                cout<<BOLDGREEN;
                cout<<"True"<<endl;
            }else{
                cout<<BOLDRED;
                cout<<"False"<<endl;
            }
            counter++;
        }

        p = p->next;
    }
    if(noUsers){
        cout<<RED;
        cout<<"       NO USERS LOGGED"<<endl;

    }
    cout<<RESET<<endl;
}

/**
 * This method will print the list of registered clients and their info.
 *
 */
void Server::printListofUsers() {
    cout << "\033[1;34m";
    User* p = listOfUsers;
    cout<<"[SERVER] LIST OF USERS"<<endl;
    int counter = 1;
    while(p){
        cout << "\033[1;34m";
        cout<<counter<<") Username: ";
        cout << "\033[1;37m";
        cout<<p->Username<<endl;
        cout << "\033[1;34m";
        cout<<"   Public Key path: "<<p->PublicKeyPath<<endl;
        cout<<"   Logged: ";
        if(p->logged){
            cout << "\033[1;32m";
            cout<<"True"<<endl;
        }else{
            cout << "\033[1;31m";
            cout<<"False"<<endl;
        }
        cout << "\033[1;34m";
        cout<<"   inGame: ";
        if(p->inGame){
            cout << "\033[1;32m";
            cout<<"True"<<endl;
        }else{
            cout << "\033[1;31m";
            cout<<"False"<<endl;
        }
        p = p->next;
        counter++;
    }
    cout <<"\033[0m\n";
}

/**
 * This method will print the network information: IP AND PORT of the server
 *
 */
void Server::printServerNetworkParams() {
    cout<<"Network Parameters:"<<endl;
    char * addr = inet_ntoa(this->srv_addr.sin_addr);
    cout<<" IP ADDRESS: "<<addr<<endl;
    int port = ntohs(this->srv_addr.sin_port);
    cout<<" PORT: "<<port<<endl;
    cout<<endl;
}
/**
 * This method will print the possible commands for the server
 *
 *
 */
void Server::printCommands() {
    cout<<BOLDCYAN;
    cout<<"---------------COMMANDS---------------"<<endl;
    cout<<"1) USERS: Print list of users."<<endl;
    cout<<"2) USERSLOGGED: Print list of logged users."<<endl;
    cout<<"3) EXIT: To stop the server. Eventual current game will be not stopped."<<endl;
    cout<<"4) C: Print the list of commands."<<endl;
    cout<<"--------------------------------------"<<endl;

}
/**
 * Check the command set in input
 *
 * @param com
 */
void Server::checkCommand(string com) {
    if(!com.compare("USERS")){
        printListofUsers();
    }else if(!com.compare("USERSLOGGED")){
        printListofLoggedUsers();
    }else if(!com.compare("EXIT")){
        exit(0);
    }else if(!com.compare("C")) {
        printCommands();
    }else{
        cout<<"[SERVER] Command not found."<<endl;
    }
}

User* Server::searchConnectedClientByUsername(string username) {
    User* p = listOfUsers;
    while(p){
        if(p->Username.compare(username) == 0){
            return p;
        }
        p = p->next;
    }
    return nullptr;
}

EVP_PKEY* Server::fetchPublicKey(string path){
    cout<<"[SERVER] Reading User's Public Key"<<endl;

    FILE* file = fopen(path.c_str(), "r");
    if(!file){
        cerr<<"ERROR READING FILE."<<endl;
        cerr<<"Closing..."<<endl;
        exit(1);
    }
    EVP_PKEY* pubKey = PEM_read_PUBKEY(file, NULL, NULL,NULL);
    if(!pubKey){
        ERR_print_errors_fp(stderr);
        cerr<<"ERROR READING PRIVATE KEY FILE."<<endl;
        cerr<<"Closing..."<<endl;
        exit(1);
    }
    fclose(file);
    return pubKey;
}


User* Server::searchConnectedClientBySocketNumber(int sock_num){
    User* p = listOfUsers;
    while(p){
        if(p->client_socket == sock_num){
            return p;
        }
        p = p->next;
    }
    return nullptr;
}


int Server::searchNewClientInWaitingListBySocketNumber(vector<WaitingClientConnection> v, int sock_num) {

    for(unsigned int i = 0; i< v.size();i++){
        if(v.at(i).client_socket == sock_num){
            return i;
        }
    }
    return -1;

}

unsigned char* Server::serializeListOfLoggedUsers(size_t& len) {
    User* p = listOfUsers;
    int counter = 0;
    while(p){
        if(p->logged)
            counter++;
        p = p->next;
    }
    len = USERNAME_SIZE_MAX*counter;
    unsigned char* list = (unsigned char*)malloc(USERNAME_SIZE_MAX*counter);
    if(!list){return nullptr;}
    int c = 0;
    p = listOfUsers;
    while(c < counter ){
        if(p->logged){
            char* ID = (char*)malloc(USERNAME_SIZE_MAX*sizeof(uint8_t));
            if(!ID){cout<<"[ERROR] MEM ALLOC."; exit(1);}
            memset(ID,0, USERNAME_SIZE_MAX);
            strcpy(ID, p->Username.c_str());
            memcpy(&list[c*USERNAME_SIZE_MAX], ID, USERNAME_SIZE_MAX);
            c++;
            free(ID);
        }
        p = p->next;
    }
    len = counter*USERNAME_SIZE_MAX;
    return list;
}