//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_NETWORKMONITOR_H
#define INC_8505_A3_BACKDOOR_NETWORKMONITOR_H

#include <string>
#include "TrafficAnalyzer.h"

using namespace std;

class NetworkMonitor {

private:
    TrafficAnalyzer * trafficAnalyzer;

public:
    NetworkMonitor(TrafficAnalyzer * trafficAnalyzer);

    string listenForTraffic();


};


#endif //INC_8505_A3_BACKDOOR_NETWORKMONITOR_H
