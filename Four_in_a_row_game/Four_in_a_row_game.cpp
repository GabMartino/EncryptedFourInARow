//
// Created by gabriele on 27/01/21.
//

#include "Four_in_a_row_game.h"

int pth (int x,int y)  {
    return sqrt (pow(x,2)+pow(y,2));
}
void Four_in_a_row_game::printGameBoard(){
    int n = 7;

    int c=0;
    int r= this->size;

    const int width=r;
    const int length=r*1.5;
    cout<<BLUE;
    int counter = 0;
    for( int j = 0; j< ROWS; j++){
        for (int y=width;y >= -width;y-=2) {
            cout<<"|";
            for (int i = 0; i < COLUMNS; i++) {
                if(matrix[j][i] == 1){
                    cout<<BOLDRED;
                }else if(matrix[j][i] == 2){
                    cout<<BOLDGREEN;
                }else if(matrix[j][i] == 3) {
                        cout<<BOLDYELLOW;
                }else{
                    cout<<BLUE;

                }

                for (int x = -length; x <= length; x++) {
                    if ((int) pth(x, y) == r ) cout << "@";
                    else if ((int) pth(x, y) < r and matrix[j][i] != 0) cout << "@";
                    else cout << " ";

                }

                cout<<BLUE;
                cout<<"|";

                counter++;
            }

            cout<<endl;

        }

        for(int k = 0; k< counter; k++){
            cout<<"--";
        }
        for(int k = 0; k< counter/2; k++){
            cout<<"-";
        }
        cout<<endl;
        counter = 0;
    }
    cout<<RESET<<endl;

}

bool Four_in_a_row_game::setYourCoin(unsigned int value) {
    if(value > SIZE_MAX/sizeof(unsigned int) || value < 1 || value > 7){
        cout<<"Value not valid."<<endl;
        cout<<"Insert a value in [1,7]"<<endl;
    }
    value -= 1;
    return setIDCoin(value, yourID);

}

bool Four_in_a_row_game::setAdvCoin(unsigned int value) {
    if(value > SIZE_MAX/sizeof(unsigned int) || value < 1 || value > 7){
        cout<<"Value not valid."<<endl;
        cout<<"Insert a value in [1,7]"<<endl;
    }

    value -= 1;
    return setIDCoin(value, adversaryID);
}
bool Four_in_a_row_game::setIDCoin(int value, int ID) {
    if(matrix[0][value] != 0){
        cout<<"COLUMN FULL"<<endl;
        cout<<"Try another column"<<endl;
        return false;
    }
    for(int i = ROWS - 1; i>= 0; i--){
        if(matrix[i][value] == 0){
            matrix[i][value] = ID;
            break;
        }
    }
    return checkWin(ID);
}

bool Four_in_a_row_game::checkWin(unsigned int ID) {
    int trackRows[4];
    int trackColumn[4];
    memset(&trackRows, 0, 4*sizeof(int));
    memset(&trackColumn, 0, 4*sizeof(int));
    //---------------------------------------CHECK ALL THE ROWS

    int counter = 0;
    for(int i = 0; i<ROWS; i++){
        counter = 0;
        for(int j = 0; j<COLUMNS;j++){
            if(matrix[i][j] == ID){
                trackRows[counter] = i;
                trackColumn[counter] = j;
                counter++;
            }else{
                counter = 0;
            }
            if(counter >= 4){

                win = true;
                break;
            }
        }
        if(win){
            break;
        }
    }
    //--------------------------------------CHECK ALL THE COLUMNS
    if(!win){
        memset(&trackRows, 0, 4*sizeof(int));
        memset(&trackColumn, 0, 4*sizeof(int));
        for(int i = 0; i<COLUMNS; i++){
            counter = 0;
            for(int j = 0; j<ROWS;j++){
                if(matrix[j][i] == ID){
                    trackRows[counter] = j;
                    trackColumn[counter] = i;
                    counter++;
                }else{
                    counter = 0;
                }
                if(counter >= 4){

                    win = true;
                    break;
                }
            }
            if(win){
                break;
            }
        }
    }
    //CHECK ALL THE TOP LEFT-> BOTTOM RIGHT DIAGONAL
    if(!win){
        memset(&trackRows, 0, 4*sizeof(int));
        memset(&trackColumn, 0, 4*sizeof(int));

        for(int shiftR = 0 ; shiftR< ROWS; shiftR++){
            if(shiftR >= ROWS - 3){
                break;
            }

            for(int shiftC = 0 ; shiftC< COLUMNS; shiftC++){
                if(shiftC>= COLUMNS - 3){
                    break;
                }
                counter = 0;
                for(int i = 0; i < ROWS; i++){
                    if(i%COLUMNS + shiftC >= COLUMNS ){
                        break;
                    }
                    if((i%ROWS + shiftR) >=ROWS ){
                        break;
                    }
                    if(matrix[(i%ROWS + shiftR)%ROWS][(i%COLUMNS + shiftC)%COLUMNS] == ID){

                        trackRows[counter] = (i%ROWS + shiftR)%ROWS;
                        trackColumn[counter] = (i%COLUMNS + shiftC)%COLUMNS;
                        counter++;
                    }else{
                        counter = 0;
                    }
                    if(counter>=4){

                        win = true;
                        break;
                    }
                }
                if(win){
                    break;
                }
            }
            if(win){
                break;
            }
        }

    }
    //------------------CHECK ALL THE BOTTOM LEFT -> TOP RIGHT DIAGONALS
    if(!win){
        memset(&trackRows, 0, 4*sizeof(int));
        memset(&trackColumn, 0, 4*sizeof(int));
        counter = 0;
        for(int shiftR = 0 ; shiftR< ROWS; shiftR++){
            if(shiftR >= ROWS - 3){
                break;
            }
            counter = 0;
            for(int shiftC = 0 ; shiftC< COLUMNS; shiftC++){
                if(shiftC>= COLUMNS - 3){
                    break;
                }
                for(int i = 0; i < ROWS; i++){
                    if(i%COLUMNS + shiftC >= COLUMNS ){
                        break;
                    }
                    if((i%ROWS + shiftR) >=ROWS ){
                        break;
                    }
                    if(matrix[((ROWS - 1 - i)%ROWS - shiftR)%ROWS][(i%COLUMNS + shiftC)%COLUMNS] == ID){
                        trackRows[counter] = ((ROWS - 1 - i)%ROWS - shiftR)%ROWS;
                        trackColumn[counter] = (i%COLUMNS + shiftC)%COLUMNS;
                        counter++;
                    }else{
                        counter = 0;
                    }
                    if(counter>=4){

                        win = true;
                        break;
                    }
                }
                if(win){
                    break;
                }
            }
            if(win){
                break;
            }
        }



    }


    //memset(matrix, 0, sizeof(matrix[0][0]) * ROWS* COLUMNS);
    if(win){

        for(int i = 0; i< 4;i++){
            matrix[trackRows[i]][trackColumn[i]] = 3;
        }
        winner = ID;
        printGameBoard();
        if(winner == yourID){
            printYouWin();
        }else{
            printYouLose();
        }
    }
    return win;
}

void Four_in_a_row_game::printYouWin() {

    cout<<BOLDGREEN;
    cout<<"__   _____  _   _  __        _____ _   _   _ \n"
        "\\ \\ / / _ \\| | | | \\ \\      / /_ _| \\ | | | |\n"
        " \\ V / | | | | | |  \\ \\ /\\ / / | ||  \\| | | |\n"
        "  | || |_| | |_| |   \\ V  V /  | || |\\  | |_|\n"
        "  |_| \\___/ \\___/     \\_/\\_/  |___|_| \\_| (_)"<<endl;

    cout<<RESET<<endl;
}

void Four_in_a_row_game::printYouLose() {

    cout<<BOLDRED;
    cout<<"__   _____  _   _   _     ___  ____  _____   _ \n"
          "\\ \\ / / _ \\| | | | | |   / _ \\/ ___|| ____| | |\n"
          " \\ V / | | | | | | | |  | | | \\___ \\|  _|   | |\n"
          "  | || |_| | |_| | | |__| |_| |___) | |___  |_|\n"
          "  |_| \\___/ \\___/  |_____\\___/|____/|_____| (_)\n"
          "                                               "<<endl;
    cout<<RESET<<endl;
}

void Four_in_a_row_game::printHeader() {
    cout<<BOLDCYAN;
    cout<<"__        _______ _     ____ ___  __  __ _____   ___ _   _ \n"
          "\\ \\      / / ____| |   / ___/ _ \\|  \\/  | ____| |_ _| \\ | |\n"
          " \\ \\ /\\ / /|  _| | |  | |  | | | | |\\/| |  _|    | ||  \\| |\n"
          "  \\ V  V / | |___| |__| |__| |_| | |  | | |___   | || |\\  |\n"
          "   \\_/\\_/  |_____|_____\\____\\___/|_|  |_|_____| |___|_| \\_|\n"
          "                                                           \n"
          " _____ ___  _   _ ____    ___ _   _      _      ____   _____        __\n"
          "|  ___/ _ \\| | | |  _ \\  |_ _| \\ | |    / \\    |  _ \\ / _ \\ \\      / /\n"
          "| |_ | | | | | | | |_) |  | ||  \\| |   / _ \\   | |_) | | | \\ \\ /\\ / / \n"
          "|  _|| |_| | |_| |  _ <   | || |\\  |  / ___ \\  |  _ <| |_| |\\ V  V /  \n"
          "|_|   \\___/ \\___/|_| \\_\\ |___|_| \\_| /_/   \\_\\ |_| \\_\\\\___/  \\_/\\_/   "<<endl;
    cout<<RESET<<endl;
}

