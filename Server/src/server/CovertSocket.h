//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_COVERTSOCKET_H
#define INC_8505_A3_BACKDOOR_COVERTSOCKET_H

#include <string>
#include "TrafficAnalyzer.h"

using namespace std;

class CovertSocket {

private:
    CovertSocket();

    static CovertSocket * instance;

    int rawSocket;

    void ChangetoDnsNameFormat(char* dns, char* host);

public:

    static CovertSocket * getInstance();

    void send(string data);

    unsigned short csum(unsigned short *ptr, int nbytes);

};


#endif //INC_8505_A3_BACKDOOR_COVERTSOCKET_H
