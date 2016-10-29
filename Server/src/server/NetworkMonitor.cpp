//
// Created by bensoer on 18/10/16.
//

#include "NetworkMonitor.h"
#include "../utils/Logger.h"
#include "../utils/Structures.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <iostream>

NetworkMonitor * NetworkMonitor::instance = nullptr;

NetworkMonitor::NetworkMonitor() {
}

NetworkMonitor * NetworkMonitor::getInstance() {
    if(NetworkMonitor::instance == nullptr){
        NetworkMonitor::instance = new NetworkMonitor();
    }

    return NetworkMonitor::instance;
}

void NetworkMonitor::packetCallback(u_char* ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet){

    Logger::debug("Packet Found. Now Parsing");

    char * ptr;

    struct sniff_ethernet * ethernet = (struct sniff_ethernet*)(packet);
    struct sniff_ip * ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip) * 4;
    struct udphdr * udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);
    u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);

    Logger::debug("Structures Found Over Packet");
    //check if it is our packet - has dest port of 4378
    short destinationPort = ntohs(udp->uh_dport);
    printf("%d\n", destinationPort);

    //if our packet. parse what we know out of it
    printf("%s\n", payload);

    NetworkMonitor::instance->data = new string((char *)payload);
    NetworkMonitor::instance->killListening();

}

void NetworkMonitor::killListening() {
    if(this->currentFD != nullptr){
        pcap_breakloop(this->currentFD);
    }
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
    string filter = "udp dst port 0";
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
    pcap_loop(this->currentFD, 0, NetworkMonitor::packetCallback, args);

    if(this->data == nullptr){
        return "";
    }else{
        return (*this->data);
    }

}