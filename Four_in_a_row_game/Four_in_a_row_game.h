//
// Created by gabriele on 27/01/21.
//

#ifndef FOUR_IN_A_ROW_FOUR_IN_A_ROW_GAME_H
#define FOUR_IN_A_ROW_FOUR_IN_A_ROW_GAME_H
#include <iostream>
#include <string.h>
#include <math.h>
#include "../Utility/utils.h"

using namespace std;
#define ROWS 6
#define COLUMNS 7


class Four_in_a_row_game {
    int matrix[ROWS][COLUMNS];

    int yourID = 1;
    int adversaryID = 2;
    bool win = false;
    int winner;
    int size = 3;

public:
    Four_in_a_row_game(){
        memset(matrix, 0, sizeof(matrix[0][0]) * ROWS* COLUMNS);
    }
    bool setYourCoin(unsigned int value);
    bool setAdvCoin(unsigned int value);
    void printGameBoard();
    void printHeader();
    void increaseSize(){
        this->size = this->size + 1 < 5 ? this->size + 1 : 5;
    }
    void decreaseSize(){
        this->size = this->size - 1 > 1 ? this->size - 1 : 1;
    }

    void printYouWin();
private:
    bool setIDCoin(int value, int ID);
    bool checkWin();
    void printYouLose();
    bool checkWin(unsigned int ID);
};


#endif //FOUR_IN_A_ROW_FOUR_IN_A_ROW_GAME_H
