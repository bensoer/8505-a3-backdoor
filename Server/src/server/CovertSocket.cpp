//
// Created by bensoer on 18/10/16.
//

#include <dnet.h>
#include <cstring>
#include "CovertSocket.h"
#include "../utils/Structures.h"

#include <sys/types.h>
#include <unistd.h>

#include <netinet/ip.h>    	// IP Header definitions
#include <netinet/udp.h>
#include <iostream>

CovertSocket * CovertSocket::instance = nullptr;

CovertSocket * CovertSocket::getInstance() {
    if(CovertSocket::instance == nullptr){
        CovertSocket::instance = new CovertSocket();
    }

    return CovertSocket::instance;
}

CovertSocket::CovertSocket() {

    //constructor
    this->rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg = 1;
    if (setsockopt (this->rawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        perror("setsockopt");
    }

}

void CovertSocket::send(string data) {

    cout << "DATA To BE SENT IS: >" << data << "<" << endl;
    cout << "DATA LENGTH: >" << data.length() << "<" << endl;
    cout << "DATA SIZE: >" << sizeof(strlen(data.c_str()) * sizeof(char)) << "<" << endl;

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
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

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
    ip->saddr = inet_addr ("127.0.0.1");  //Source IP address
    ip->daddr = sin.sin_addr.s_addr;

    ip->check = this->csum((unsigned short *) datagram, ip->tot_len >> 1);

    //UDP Header Fields
    udp->dest = htons(53);
    //udp->source
    udp->source = htons(4378);

    printf("UDP Size: %d ", sizeof(*udp) + data.size());
    printf("UDP Header: %d ", sizeof(*udp));
    printf("UDP Payload: %d\n", data.size());

    //udp->len = htons(sizeof(*udp) + data.size());
    //udp->uh_sum = htons(sizeof(*udp) + data.size());
    udp->uh_sum = htons(sizeof(*udp) + sizeof(*dns) + data.size() + sizeof(struct QUESTION));
    udp->len = htons(sizeof(*udp) + sizeof(*dns) + data.size() + sizeof(struct QUESTION));
    udp->check = 0;

    //Pseudo Header
    psh.dest_address = sin.sin_addr.s_addr;
    psh.source_address = inet_addr("127.0.0.1");
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

    strcpy(query, data.c_str());

    //char * writable = new char[data.size() + 1];
    //std::copy(data.begin(), data.end(), writable);
    //writable[data.size()] = '\0'; // don't forget the terminating 0

    //ChangetoDnsNameFormat(query, writable);

    struct QUESTION *dnsq = (struct QUESTION *)(datagram + sizeof(*ip) + sizeof(*udp) + sizeof(*dns) + data.size());

    dnsq->qtype = htons(1); // 1 for IPv4 lookup
    dnsq->qclass = htons(1); //1 for internet class


    //IP_HDRINCL to stop the kernel from building the packet headers
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            perror("setsockopt");
    }

    //Send the packet
    if (sendto (this->rawSocket, datagram, ip->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("sendto");
    }

}

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