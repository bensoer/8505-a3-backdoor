// Use pcap_findalldevs to find system interfaces

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h> 

char errbuf[PCAP_ERRBUF_SIZE];
void show_interfaces(void);

int main (int argc, char *argv[])
{
    show_interfaces();
    return 0;
}    

void show_interfaces(void)
{
           pcap_if_t *interface_list;
           pcap_if_t *if_list_ptr;
           int result;
           int i;
           
	   // Get a list of interfaces 
	   result = pcap_findalldevs (&interface_list, errbuf);
           if (result == -1) 
	   {
                fprintf(stderr, "%s\n", errbuf);
                exit(1);
           }
           
           // Display all the system interfaces
           if_list_ptr = interface_list;
           i = 0;
           while (if_list_ptr) 
	   {
                if (if_list_ptr->description) 
		{
                    printf("%d. %s (%s)\n", i, if_list_ptr->name,
                             if_list_ptr->description);
                }
                else 
		{
                    printf("%d. %s\n", i, if_list_ptr->name);
                }
                if_list_ptr = if_list_ptr->next;
                i += 1;
           }
           // free the data structures
           pcap_freealldevs(interface_list);
}
