//
// Created by bensoer on 18/10/16.
//

#include <dnet.h>
#include <cstring>
#include "CovertSocket.h"
#include "../utils/Structures.h"

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

    cout << "DDATA To BE SENT IS: >" << data << "<" << endl;
    cout << "DATA LENGTH: >" << data.length() << "<" << endl;
    cout << "DATA SIZE: >" << sizeof(strlen(data.c_str()) * sizeof(char)) << "<" << endl;

    char datagram[PKT_SIZE];
    struct iphdr *ip = (struct iphdr *) datagram;
    struct udphdr *udp = (struct udphdr *) (datagram + sizeof(*ip));
    char *payload = (char *) (datagram + sizeof(*ip) + sizeof(*udp));
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
    ip->tot_len = sizeof(struct ip) + sizeof(struct udphdr) + data.size();    // Calculate the total Datagram size
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

    udp->len = htons(sizeof(*udp) + data.size());
    udp->uh_sum = htons(sizeof(*udp) + data.size());
    udp->check = 0;

    //Pseudo Header
    psh.dest_address = sin.sin_addr.s_addr;
    psh.source_address = inet_addr("127.0.0.1");
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;

    memcpy(&psh.udp, udp, sizeof(struct udphdr));
    udp->check = csum((unsigned short *) &udp, sizeof(pseudo_header));

    memcpy(payload, data.c_str(), data.size());


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