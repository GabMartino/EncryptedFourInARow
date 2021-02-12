
#include "Server.hpp"


int main(int argc, char* argv[]){
    cout<<BOLDBLUE<<endl;
    cout<<"------------------------------------------------------------------------FOUR IN A ROW SERVER INITIALIZATION------------------------------------------------------------------------"<<endl;
    cout<<RESET<<endl;
    if(argc < 5){
        cout<<"Missing parameters."<<endl;
        exit(1);
    }
    string DB_users_pub_keyspath = argv[1];
    string Server_certificate_path = argv[2];
    string Server_private_key = argv[3];
    string config_file_path = argv[4];


    Server server_(DB_users_pub_keyspath,
                   Server_certificate_path,
                   Server_private_key,
                   config_file_path);

    server_.printListofUsers();
    server_.start();

    return 0;
}