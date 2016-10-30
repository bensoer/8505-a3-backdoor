/**
 * Author: Sean H
 * 
 */

#ifndef CLIENT_NETWORKMONITOR_H
#define CLIENT_NETWORKMONITOR_H

#include <string>
#include <pcap.h>

class NetworkMonitor {
public:
    NetworkMonitor();
    static NetworkMonitor * getInstance();
    bool getInterface();
    std::string getResponse();

private:
    static NetworkMonitor * instance;
    std::string filter = "udp dst port 53"; //This is the filter that will pick out incoming packets
    pcap_if_t * listenInterface;             //This is the interface that packets will be listen on
    pcap_t * currentFD;                      //
    std::string * data;                      //
    std::string listenInterfaceName = "lo";  //This is the name of interface that packets will be listen on
    void killListening();
    static void processPayload(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);
};


#endif //CLIENT_NETWORKMONITOR_H
