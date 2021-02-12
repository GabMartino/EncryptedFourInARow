
#include "Client.h"
int main(int argc, char* argv[]) {
    cout<<BOLDBLUE<<endl;
    cout<<"------------------------------------------------------------------------FOUR IN A ROW GAME------------------------------------------------------------------------"<<endl;
    cout<<RESET<<endl;
    if(argc < 5){
        cout<<"Missing parameters."<<endl;
        exit(1);
    }
    string DB_users_priv_keyspath = argv[1];
    string CA_certificate_path = argv[2];
    string CA_crl_path = argv[3];
    string config_file_path = argv[4];
    if(DB_users_priv_keyspath.empty() or CA_certificate_path.empty() or CA_crl_path.empty() or config_file_path.empty()){
        cout<<"Missing parameters."<<endl;
        exit(1);
    }
    if(argc <= 5){
        Client client_(DB_users_priv_keyspath,
                       CA_certificate_path,
                       CA_crl_path,
                       config_file_path);
        client_.login();
        if(client_.connectToServer() and client_.authenticate()){
            client_.start();
        }
    }else{
        string name = argv[5];
        string pass = argv[6];
        if(name.empty() or pass.empty()){
            cout<<"Missing parameters"<<endl;
            exit(1);
        }
        Client client_(DB_users_priv_keyspath,
                       CA_certificate_path,
                       CA_crl_path,
                       config_file_path, name, pass);
        //client_.login();
        if(client_.connectToServer() and client_.authenticate()){
            client_.start();
        }
    }








    return 0;
}
