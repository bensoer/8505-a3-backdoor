/**
 * Author: Sean H
 * 
 */

#include <pcap/pcap.h>
#include <iostream>
#include <string.h>
#include "NetworkMonitor.h"
#include "../utils/Logger.h"
#include "../utils/Structures.h"

NetworkMonitor * NetworkMonitor::instance = nullptr;

NetworkMonitor::NetworkMonitor()
{
    this->listenInterface = nullptr;
    this->currentFD = nullptr;
    this->data = nullptr;
}

NetworkMonitor * NetworkMonitor::getInstance()
{
    if(NetworkMonitor::instance == nullptr){
        NetworkMonitor::instance = new NetworkMonitor();
    }
    return NetworkMonitor::instance;
}


std::string NetworkMonitor::getResponse()
{
    std::string response;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    //fetch network information for interface
    pcap_lookupnet(this->listenInterface->name, &subnetMask, &ip, errbuf);

    //open up a raw socket and listen in promisc mode on it for data

    if((this->currentFD = pcap_open_live(this->listenInterface->name, BUFSIZ, 1, -1, errbuf)) == NULL){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error in pcap_open_live");
        Logger::error(string(errbuf));
        return "-1";
    }

    //setup the libpcap filter
    struct bpf_program fp;
    //compile the filter
    if(pcap_compile(this->currentFD, &fp, this->filter.c_str(), 0, ip) == -1){
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
    pcap_loop(this->currentFD, 0, NetworkMonitor::processPayload, args);

    if(this->data == nullptr){
        return this->data->c_str();
    }else{
        return (*this->data);
    }
}

bool NetworkMonitor::getInterface(){

    Logger::debug("Main:getInterfaces - Initializing");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces;
    pcap_if_t * interface;
    pcap_if_t *allInterfaces;

    Logger::debug("Main:getInterfaces - Finding All Interfaces");

    if(pcap_findalldevs(&interfaces, errbuf) == -1){
        Logger::error("NetworkMonitor::getInterface - There Was An Error Fetching The Interfaces");
        return false;
    }

    allInterfaces = interfaces;
    interface = interfaces;
    while(interface != NULL)
    {
        const char * name = interface->name; //Get the interface name
        if(strcmp(name, string(this->listenInterfaceName).c_str()) == 0) //Check if it is the right interface
        {
            Logger::debug("Correct interface found: " + this->listenInterfaceName);
            this->listenInterface = interface; //This will set the listen interface
            return true;
        }
        interface = interface->next; //If it is not then loop again
    }
    return false; //This will happen if the right interface can never be found
}

void NetworkMonitor::processPayload(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet)
{
    Logger::debug("Packet reviced");

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


void NetworkMonitor::killListening()
{
    if(this->currentFD != nullptr){
        pcap_breakloop(this->currentFD);
    }
}