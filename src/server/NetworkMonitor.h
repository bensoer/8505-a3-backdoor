//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_NETWORKMONITOR_H
#define INC_8505_A3_BACKDOOR_NETWORKMONITOR_H

#include <string>
#include <pcap.h>
#include "TrafficAnalyzer.h"

using namespace std;

class NetworkMonitor {

private:
    TrafficAnalyzer * trafficAnalyzer;

    NetworkMonitor * listeningInstance;

    pcap_t * currentFD;

    static void packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);

public:
    NetworkMonitor(TrafficAnalyzer * trafficAnalyzer);

    string listenForTraffic(pcap_if_t * listeningInterface);

    void killListening();


};


#endif //INC_8505_A3_BACKDOOR_NETWORKMONITOR_H
