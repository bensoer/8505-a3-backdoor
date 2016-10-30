/**
 * Author: Sean H
 * 
 */

#ifndef CLIENT_COVERTSOCKET_H
#define CLIENT_COVERTSOCKET_H

#include <string>

class CovertSocket
{
public:
    CovertSocket(std::string connectionIPAddress);
    int sendCommand(std::string);
private:
    std::string connectionIPAddress;
    int rawSocket;
    int dstPort = 100;
    int srcPort = 4567;
    std::string srcIP = "127.0.0.1";

    unsigned short csum (unsigned short *ptr,int nbytes);
};


#endif //CLIENT_COVERTSOCKET_H
