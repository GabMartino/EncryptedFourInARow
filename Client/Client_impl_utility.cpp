//
// Created by gabriele on 25/01/21.
//

#include "Client.h"



SecureConnectionServlet Client::servlet_;

void Client::login() {
    cout<<BLUE;
    cout<<"---------------------------LOGIN---------------------------"<<endl;
    bool found = false;
    while(!found){
        cout<<"[If you don't want to play anymore and close the game, type 'EXIT']"<<endl;
        cout<<"Username:"<<endl;
        cin>> this->username;
        if(this->username.size() >= USERNAME_SIZE_MAX){
            cout<<"[CLIENT][ERROR] Username is too big."<<endl;
            continue;
        }
        if(this->username.compare("EXIT")== 0){
            cout<<"[CLIENT]Closing.."<<endl;
            exit(0);
        }
        found = searchUserInFile();

    }
    string name;
    getline(std::cin, name);
    store = X509_STORE_new();
    //searchUserInFile();
    fetchPrivateKeyFromFile();
    fetchCACertificateAndCRLFromFile();
    fetchAndSetNetParams();
    cout<<RESET<<endl;
}
void Client::fetchPrivateKeyFromFile() {
    cout<<"[CLIENT]"<<"["<<this->username<<"] ";
    cout<<"Fetching Private key from file"<<endl;
    FILE* file = fopen(this->privateKey_path.c_str(), "r");
    if(!file){

        cout<<"[ERROR] ERROR READING FILE."<<endl;
        cerr<<"[ERROR] Closing..."<<endl;
        exit(1);
    }

    if(!this->password.empty()){
        if(!PEM_read_PrivateKey(file, &this->prvkey, NULL, (void *) (const char *) this->password.c_str())){
            ERR_print_errors_fp(stderr);
            cerr<<"[ERROR] ERROR READING PRIVATE KEY FILE."<<endl;
            cerr<<"[ERROR] Closing..."<<endl;
            exit(1);
        }
    }else{
        if(!PEM_read_PrivateKey(file,&this->prvkey,NULL, NULL)){
            ERR_print_errors_fp(stderr);
            cerr<<"[ERROR] ERROR READING PRIVATE KEY FILE."<<endl;
            cerr<<"[ERROR] Closing..."<<endl;
            exit(1);
        }
    }
    fclose(file);

}

bool Client::searchUserInFile() {
    cout<<MAGENTA;
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Check the user existance."<<endl;
    xml_document<> doc;
    xml_node<> * root_node = NULL;
    // Read the sample.xml file
    ifstream theFile (this->DB_path_file);
    vector<char> buffer((istreambuf_iterator<char>(theFile)), istreambuf_iterator<char>());
    buffer.push_back('\0');

    // Parse the buffer
    doc.parse<0>(&buffer[0]);
    // Find out the root node
    root_node = doc.first_node("DB_USERS");
    if(!root_node){
        cout<<"[ERROR] Error reading root node"<<endl;
        exit(1);
    }
    bool found = false;
    xml_node<>* user_node= root_node->first_node("User");
    while(user_node){
        xml_node<>* user_name_node = user_node->first_node("Name");
        if(user_name_node){
            if(((string)user_name_node->value()).compare(this->username)== 0){
                found = true;
                this->privateKey_path = (string) user_node->first_node("Private_key_path")->value();
                return found;
            }
        }
        user_node = user_node->next_sibling();
    }
    if(!found){
        cout<<"[ERROR] A User with this name has not been found."<<endl;
    }
    return found;
    cout<<RESET<<endl;
}

void Client::fetchCACertificateAndCRLFromFile(){
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Fetching CA's certificate from file and extracting public key..."<<endl;
    X509* cert;
    FILE* file = fopen(this->ca_certificate_path_file.c_str(), "r");
    if(!file){
        cerr<<"[CLIENT] ERROR READING FILE."<<endl;
        cerr<<"Closing..."<<endl;
        exit(1);
    }
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    if(!cert){
        ERR_print_errors_fp(stderr);
        cerr<<"[CLIENT] ERROR READING CERTIFICATE FILE."<<endl;
        cerr<<"Closing..."<<endl;
        exit(1);
    }
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" CA Certificate extracted."<<endl;
    // CRL
    X509_CRL* crl;
    FILE* file_crl = fopen(this->ca_crl_path_file.c_str(), "r");
    if(!file_crl){
        cerr<<"[CLIENT] ERROR READING FILE."<<endl;
        cerr<<"[CLIENT] Closing..."<<endl;
        exit(1);
    }
    crl = PEM_read_X509_CRL(file_crl, NULL, NULL, NULL);
    if(!crl){
        ERR_print_errors_fp(stderr);
        cerr<<"[CLIENT] ERROR READING CERTIFICATE FILE."<<endl;
        cerr<<"[CLIENT] Closing..."<<endl;
        exit(1);
    }
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" CRL Certificate extracted."<<endl;
    X509_STORE_add_cert(this->store, cert);
    X509_STORE_add_crl(this->store, crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Store's Certificates created."<<endl;
    //X509_STORE_free(store) //to close the store

    fclose(file);
}

void Client::fetchAndSetNetParams() {
    cout<<"[CLIENT]"<<"["<<this->username<<"]"<<" Fetching Server Parameters..."<<endl;
    xml_document<> doc;
    xml_node<> * root_node = NULL;
    // Read the sample.xml file
    ifstream theFile (this->serverParams_path);
    vector<char> buffer((istreambuf_iterator<char>(theFile)), istreambuf_iterator<char>());
    buffer.push_back('\0');

    // Parse the buffer
    doc.parse<0>(&buffer[0]);
    // Find out the root node
    root_node = doc.first_node("SERVER_PARAMS");
    if(!root_node){
        cerr<<"Error reading root node"<<endl;
        return;
    }
    string ip = (string)(root_node->first_node("IP_ADDRESS")->value());
    int ret = inet_pton(AF_INET, ip.c_str(), &this->server_params.sin_addr);
    if(ret <= 0){
        cerr<<"[CLIENT] ERROR PARSING SERVER IP ADDRESS"<<endl;
        return;
    }
    int port = atoi(root_node->first_node("PORT")->value());
    if(port <= 0 || port > 65535){
        cerr<<"[CLIENT] ERROR PARSING SERVER PORT"<<endl;
        return;
    }
    this->server_params.sin_family = AF_INET;
    this->server_params.sin_port = htons(port);
}

int Client::checkCommand(string com){
    if(!com.compare("USERS")){
        return 1;
    }else if(!com.compare("PLAY")){
        return 2;
    }else if(!com.compare("EXIT")){
        return 3;

    }
    return -1;

}
void Client::printCommands() {
    cout<<"------------COMMANDS------------"<<endl;
    cout<<"1) USERS : To require the list of logged users."<<endl;
    cout<<"2) PLAY  : To require to play with some logged user."<<endl;
    cout<<"           Then type the username of the user you want to play with."<<endl;
    cout<<"3) EXIT  : If you want to stop the game and exit."<<endl;
    cout<<"--------------------------------"<<endl;
}
