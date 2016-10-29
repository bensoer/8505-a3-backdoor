#include <iostream>
#include <string.h>

#include "../utils/Logger.h"
#include "TrafficAnalyzer.h"
#include "NetworkMonitor.h"

int setArgs(int, char**);

const bool debug = true;
std::string backdoorIP;

int main(int argc, char* argv[])
{
    int result;

    Logger::setDebug(debug);
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

    

    return 0;
}

/**
 * This will get the command line args and set them as variables for use in main
 */
int setArgs(int argc, char* argv[])
{
    if(argc < 2 or argc > 3) //This checks if the valid amount of args are passed in (valid arg numbers: 1 extra)
    {
        Logger::error("Invalid number or args inputted");
        return 1;
    }

    if(strcmp(argv[1], "-h"))
    {
        std::cout << "Usage:" << std::endl <<
                     "For help: " <<  argv[0] << " -h" << std::endl <<
                     "For connection: " << argv[0] << " IP_address" << std::endl;
        return 2;
    }
    backdoorIP = argv[1]; //Set the first arg as the server IP


}