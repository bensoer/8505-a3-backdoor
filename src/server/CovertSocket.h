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
    TrafficAnalyzer * trafficAnalyzer;

public:
    CovertSocket(TrafficAnalyzer * trafficAnalyzer);

    void send(string data);

    string recv();
};


#endif //INC_8505_A3_BACKDOOR_COVERTSOCKET_H
