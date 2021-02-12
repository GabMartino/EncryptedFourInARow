//
// Created by gabriele on 28/01/21.
//

#include "Client.h"
#include <limits>

Four_in_a_row_game Client::game_;

void Client::play(bool yourTurn) {

    game_.printHeader();
    cout<<BOLDCYAN;
    printCommandsInGame();
    fd_set readfds;
    int max_sd ;
    int activity;
    string command;
    cin.clear();
    cout<<"Who accepted plays first"<<endl;

    while(1){
        cout<<BOLDCYAN;
        cout<<endl;
        if(yourTurn){
            cout<<"PLAY>>";
        }else{
            cout<<"WAIT"<<endl;
        }
        cout.flush();
        FD_ZERO(&readfds);//clear the socket set
        if(yourTurn){
            FD_SET(STDIN_FILENO, &readfds);//insert
            cin.clear();
        }
        FD_SET(this->adv_socket, &readfds);
        max_sd = this->adv_socket > STDIN_FILENO ?  this->adv_socket : STDIN_FILENO;
        //printCommands();
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if(activity < 0){
            cout<<"[ERROR] Error socket."<<endl;
            cout<<strerror(errno)<<endl;
            closeGameSession();
            return ;
        }
        if(FD_ISSET(STDIN_FILENO, &readfds)){
            cout<<BOLDCYAN;
            cin>>command;
            if(!cin){
                cout<<"Input Error."<<endl;
                cin.clear();
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                continue;
            }
            int ret = checkCommandInGame(command);
            if(ret == 1){
                cout<<"MOVE SENT"<<endl;
                game_.printGameBoard();
                yourTurn = false;
            }else if(ret == -1){
                cout<<"ERROR SENDING MOVE"<<endl;
            }else if(ret == 0){
                cout<<"CLOSING GAME"<<endl;
                closeGameSession();
                return;
            }else if(ret == 3){
                cout<<BOLDCYAN;
                cout<<"GAME ENDS"<<endl;
                cout<<"CLOSING GAME, If you want to replay you have to start a new request."<<endl;
                closeGameSession();
                return;
            }

        }else if(FD_ISSET(this->adv_socket, &readfds)){
            cout<<BOLDCYAN;
            unsigned char received_msg[BUFF_MAX_SIZE];
            memset(received_msg, 0, BUFF_MAX_SIZE);
            socklen_t cli_addr_size = sizeof(this->adv_params);
            int ret = recvfrom(this->adv_socket, received_msg, BUFF_MAX_SIZE, 0,(sockaddr *) &this->adv_params,&cli_addr_size);
            if(ret == -1){cout<<"[ERROR] Error receiving msg."<<endl; closeGameSession(); return;}
            if(ret == 0){cout<<"[ERROR] Adversary  socket closed."<<endl;  game_.printYouWin();
                cout<<BOLDCYAN;
                cout<<"THE PLAYER IS DISCONNECTED."<<endl; closeGameSession();return;}

            uint16_t move;
            ret = handleAdvMessage(received_msg, ret, move);
            if(ret == 1){
                if(game_.setAdvCoin(move)){
                    cout<<BOLDCYAN;
                    cout<<"GAME ENDS"<<endl;
                    cout<<"CLOSING GAME, If you want to replay you have to start a new request."<<endl;
                    closeGameSession();
                    return ;
                }else{
                    game_.printGameBoard();
                    cout<<BOLDCYAN;
                    cout<<"----------------------------------IT'S YOUR TURN----------------------------------"<<endl;
                    cout<<"YOUR COLOR IS RED"<<endl;
                    yourTurn = true;
                }
            }else if(ret == 2){
                game_.printYouWin();
                cout<<BOLDRED;
                cout<<"THE PLAYER DISCONNECTED."<<endl;
                cout<<RESET<<endl;
                closeGameSession();
                return;
            }


        }




    }





}
void Client::printCommandsInGame(){
    cout<<"------------COMMANDS IN GAME------------"<<endl;
    cout<<"1) BOARD : If you want to print the board"<<endl;
    cout<<"2) DIM   : If you want to reduce the size of the board."<<endl;
    cout<<"3) INC   : If you want to increase the size of the board."<<endl;
    cout<<"4) MOVE  : Let you insert a number in [1,7]"<<endl;
    cout<<"5) EXIT  : If you want to stop the game and exit."<<endl;
    cout<<"----------------------------------------"<<endl;
}
int Client::checkCommandInGame(string com){
    if(!com.compare("C")){
        printCommandsInGame();
    }else if(!com.compare("BOARD")){
        game_.printGameBoard();
    }else if(!com.compare("DIM")){
        game_.decreaseSize();
    }else if(!com.compare("INC")){
        game_.increaseSize();
    }else if(!com.compare("MOVE")) {
        unsigned int move;
        bool check = false;
        while(!check){
            cout<<endl;
            cout<<"MOVE>>";
            cout.flush();
            cin>> move;
            if(cin.fail() || move > SIZE_MAX/sizeof(unsigned int) || move < 1 || move > 7 ){
                cout<<"Type a valid number"<<endl;
                cin.clear();
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            }else{
                check = true;
            }
        }
        check = sendMove(move);
        if(check){
            if(game_.setYourCoin(move)){
                return 3;
            }else{
                return 1;
            }
        }else{
            return -1;
        }
    }else if(!com.compare("EXIT")){
        sendCloseGame();
        return 0;
    }
    return 2;

}


bool Client::sendMove(uint16_t value) {
    unsigned char* move = (unsigned char*)malloc(sizeof(uint16_t));
    if(!move){
        cout<<"[ERROR] Error MEM ALLOC"<<endl;
        return false;
    }
    memset(move, 0, sizeof(uint16_t));
    memcpy(move, &value, sizeof(uint16_t));
    size_t move_msg_len;
    unsigned char* move_msg = servlet_.createAuthenticatedMsg(GAMEMOVE, this->username, this->game_key,this->iv_game,move, sizeof(uint16_t), move_msg_len,GCM);
    if(!move_msg){
        cout<<"[ERROR] Error creating new message move"<<endl;
        return false;
    }

    int ret = sendto(this->adv_socket, move_msg, move_msg_len,0,
                     (sockaddr *) &this->adv_params, sizeof(this->adv_params));
    if(ret == -1){
        cout<<"[ERROR] Error sending move"<<endl;
    }
    free(move_msg);

    return true;
}
int Client::handleAdvMessage(unsigned char *msg, size_t len, uint16_t& move) {

    if(extractMessageType(msg) == GAMEMOVE){

        unsigned char* pt = nullptr; size_t pt_len;
        bool check = servlet_.checkAuthenticatedMsg(msg, len, this->game_key, this->iv_game, pt, pt_len, GCM);
        if(!check){
            cout<<"[ERROR] Error adversary move message"<<endl;
            return -1;
        }
        memcpy(&move, pt, pt_len);

        return 1;
    }else if(extractMessageType(msg) == GAMECLOSE){
        unsigned char* dummy = nullptr; size_t dummy_len;
        bool check = servlet_.checkAuthenticatedMsg(msg, len, this->game_key, this->iv_game, dummy, dummy_len, GMAC);
        if(!check){
            cout<<"[ERROR] Error Closing game move"<<endl;
            return false;
        }

        return 2;
    }
    return -1;
}

bool Client::sendCloseGame() {
    //SEND CLOSING MESSAGE TO PEER
    size_t close_msg_len;
    unsigned char* close_msg = servlet_.createAuthenticatedMsg(GAMECLOSE, this->username, this->game_key,this->iv_game,
                                                              nullptr, 0, close_msg_len,GMAC);
    if(!close_msg){
        cout<<"[ERROR] Error creating closing msg"<<endl;
    }

    int ret = sendto(this->adv_socket, close_msg, close_msg_len,0,
                     (sockaddr *) &this->adv_params, sizeof(this->adv_params));
    if(ret == -1){
        cout<<"[ERROR] Error closing msg"<<endl;
    }
    free(close_msg);


    return true;

}

void Client::closeGameSession() {
    close(this->adv_socket);
    memset(this->adv_username, 0, USERNAME_SIZE_MAX);
    EVP_PKEY_free(this->adv_pubkey);
    EVP_PKEY_free(this->my_dh_game_session_keys);
    EVP_PKEY_free(this->adv_dh_game_session_pub_key);
    free(this->adv_nonce);
    this->adv_socket = 0;
}

