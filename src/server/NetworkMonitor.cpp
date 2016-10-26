//
// Created by bensoer on 18/10/16.
//

#include "NetworkMonitor.h"
#include "../utils/Logger.h"



NetworkMonitor::NetworkMonitor(TrafficAnalyzer * trafficAnalyzer) {
    this->trafficAnalyzer = trafficAnalyzer;
}

void NetworkMonitor::packetCallback(u_char* ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet){


    //check if it is our packet

    //if our packet. parse what we know out of it

    //if all needed is there, kill further analysis

    //else add to TrafficAnalyzer


}

void NetworkMonitor::killListening() {
    pcap_breakloop(this->currentFD);
}

string NetworkMonitor::listenForTraffic(pcap_if_t * listeningInterface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    //fetch network information for interface
    pcap_lookupnet(listeningInterface->name, &subnetMask, &ip, errbuf);

    //open up a raw socket and listen in promisc mode on it for data

    if((this->currentFD = pcap_open_live(listeningInterface->name, BUFSIZ, 1, -1, errbuf)) == NULL){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error in pcap_open_live");
        Logger::error(string(errbuf));
        return "-1";
    }

    //setup the libpcap filter
    string filter = "udp";
    struct bpf_program fp;
    //compile the filter
    if(pcap_compile(this->currentFD, &fp, filter.c_str(), 0, ip) == -1){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error Compiling The Filter");
        return "-1";
    }
    //set the filter
    if(pcap_setfilter(this->currentFD, &fp) == -1){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error Setting The Filter");
        return "-1";
    }

    u_char* args = NULL;
    //listen for UDP packets
    this->listeningInstance = this;
    pcap_loop(this->currentFD, 0, NetworkMonitor::packetCallback, args);

}