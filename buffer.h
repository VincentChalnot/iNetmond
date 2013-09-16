/* 
 * File:   buffer.h
 * Author: root
 *
 * Created on March 28, 2011, 3:51 PM
 */

/**
 * This structure is used in a linked list to buffer the incoming
 * packets.
 */
struct packet_buffer{
    unsigned long int number;
    u_char *packet;
    struct pcap_pkthdr *header;
    struct packet_buffer* next_packet;
};

//The top_packet pointer is the begining of the linked list, where the packets are processed
static struct packet_buffer* top_packet;
//The bottom_packet is the end of the list, where the captured packets are put.
static struct packet_buffer* bottom_packet;
//This variable is used to notify the threads the program is closing.
static u_char closing=0;

//Lock for accessing the top_packet pointer (there can be conflicts between the threads)
static pthread_mutex_t top_buffer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t bot_buffer_lock = PTHREAD_MUTEX_INITIALIZER;

//Lock for accessing the database
static pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;
