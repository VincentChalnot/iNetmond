/*
 * iNetmon 2 Daemon
 * Author: Vincent Chalnot, vincent.chalnot@gmail.com
 *
 * Created on March 21, 2011, 10:42 AM
 *
 * This daemon captures packet from the network and put them inside
 * a MySQL database.
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <mysql.h>
#include <time.h>

#include "protocols.h" /* Protocols codes for IPv4 & IPv6 */

static MYSQL* db; //Handler to the database
static u_int session_id; //Session id in the database (retrieved after insertion)
static pcap_t *pcap_handle; // packet capture handle
#define NUM_PACKETS 2000 // number of packets to capture
#define SNAP_LEN 1518 //default snap length (maximum bytes per packet to capture)
#define NUM_THREADS 4 //Number of threads for processing the packets
#define DISPLAY_INFOS 0 //If 0, no information is displayed about the packets
#define MYSQL_HOST "localhost"
#define MYSQL_USER "root"
#define MYSQL_PASS ""
#define MYSQL_DB "inetmon"

#include "buffer.h" //Packet buffer, contain the structure and the static variables
// Includes related to the packet processing, contains the structure and the functions to process everything
#include "arp.h"
#include "tcp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ethernet.h"

void init_db(void);
void main_loop(void);
void buffer_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_buffer(void);
u_long insert_packet(struct packet_buffer * tmp_packet);
char * gettime(void);

int main(int argc, char **argv) {
    
    char *dev = NULL; /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

    char filter_exp[] = ""; /* filter expression [3] */
    struct bpf_program fp; /* compiled filter program (expression) */
    bpf_u_int32 mask; /* subnet mask */
    bpf_u_int32 net; /* ip */
    

    // We take the filter as argument
    if (argc == 2) {
        strcpy(filter_exp, argv[1]);
    }

    // Find a capture device automatically: has to be changed
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Get network number and mask associated with capture device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // print capture info
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", NUM_PACKETS);
    printf("Filter expression: %s\n", filter_exp);

    // open capture device
    pcap_handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /*
    // make sure we're capturing on an Ethernet device [2]
    // maybe we don't need this
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet device\n", dev);
        exit(EXIT_FAILURE);
    }
    */

    // compile the filter expression
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
        exit(EXIT_FAILURE);
    }

    // apply the compiled filter
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
        exit(EXIT_FAILURE);
    }

    char * buf=gettime();
    printf("\nCapture started on %s",buf);
    
    if(DISPLAY_INFOS != 0) printf("\n num  Source MAC         Destination MAC    Protocol  Source IP                  Destination IP             Protocol\n");

    //Initialization of the database
    init_db();

    //Creating threads for packet processing
    pthread_t threads[NUM_THREADS];
    int i;
    for(i=0; i<NUM_THREADS; i++){
        pthread_create(&threads[i], NULL, (void *) &process_buffer, NULL);
    }

    //*
    pthread_t main_thread;
    pthread_attr_t main_thread_attr;
    pthread_attr_init(&main_thread_attr);
    pthread_attr_setschedpolicy(&main_thread_attr, SCHED_FIFO);
    
    //THIS IS THE MAIN LOOP
    
    pthread_create(&main_thread, &main_thread_attr, (void *) &main_loop, NULL);
    //pthread_create(&main_thread, NULL, (void *) &main_loop, NULL);

    pthread_join(main_thread, NULL); //Waiting for the end
    //*/
    //pcap_loop(pcap_handle, num_packets, buffer_packet, NULL);
    

    printf("\nClosing iNetmond...\n");
    closing=1;
    
    //Waiting for threads to terminate
    for(i=0; i<NUM_THREADS; i++){
        pthread_join(threads[i], NULL);
    }

    if(top_packet != NULL || bottom_packet != NULL){
        printf("\nError : Buffer not empty\n");
    }
    
    // cleanup everything and close the system
    pcap_freecode(&fp);
    pcap_close(pcap_handle);
    mysql_commit(db);
    mysql_close(db);

    printf("\nCapture started on : %s",buf);
    buf=gettime();
    printf("\n  And completed on : %s\n\n",buf);
    free(buf);
    buf=NULL;

    return 0;
}

void init_db(void){
    //Initialize handler to mysql connection
    db=mysql_init(NULL);

    if(db == NULL){
        printf("Error %u: %s\n", mysql_errno(db), mysql_error(db));
        exit(EXIT_FAILURE);
    }

    //Connect to the database
    if(mysql_real_connect(db, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB, 0, "/var/lib/mysql/mysql.sock", 0) == NULL){
        printf("Error connecting, code %u: %s\n", mysql_errno(db), mysql_error(db));
        exit(EXIT_FAILURE);
    }

    //New session in database -> retrieving the session_id
    char * query = (char*) malloc(70);
    sprintf(query, "INSERT INTO session (session_timestamp) VALUES (%u);", (u_int) time(NULL));
    if(mysql_query(db, query) != 0){
        printf("Error (session), code %u: %s\n", mysql_errno(db), mysql_error(db));
        exit(EXIT_FAILURE);
    } else {
        session_id = mysql_insert_id(db);
    }
    free(query);
}

void main_loop(void){
    pcap_loop(pcap_handle, NUM_PACKETS, buffer_packet, NULL);
}


/**
 * The packet buffer is a linked list of the packet_buffer
 * structure. This function is called each time a packet
 * is captured, it needs to be very small in order to not
 * lose packets. *top_packet is the top of the stack, where
 * the threads are reading, and bottom_packet is where this
 * function adds new packets.
 */
void buffer_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    static unsigned long int count = 0; // packet counter
    count++;
    pthread_mutex_lock(&bot_buffer_lock); // We lock the bottom packet in the buffer so that no other thread can access it while it's beeing modified

    struct packet_buffer * last_bottom_packet = bottom_packet; //Caching the last bottom packet

    //Allocating memory for a new packet structure in buffer
    bottom_packet = (struct packet_buffer*) malloc(sizeof (struct packet_buffer));

    // Recording the packet number in the structure
    bottom_packet->number=count;

    //We need to copy data from what's passed by pcap
    bottom_packet->header = (struct pcap_pkthdr *) malloc(sizeof (struct pcap_pkthdr)); //Allocating memory
    memcpy(bottom_packet->header, header, sizeof (struct pcap_pkthdr)); //Copying to buffer

    //Now with the packet data
    bottom_packet->packet = (u_char *) malloc(bottom_packet->header->caplen); //Allocating the buffer (with the size of the captured data)
    memcpy(bottom_packet->packet, packet, bottom_packet->header->caplen); //Copying to buffer

    //Initialize pointer to NULL
    bottom_packet->next_packet=NULL;
    
    //Buffer empty or not
    if (last_bottom_packet == NULL) { //This means the buffer is empty
        pthread_mutex_lock(&top_buffer_lock);//Locking the top buffer pointer
        top_packet = bottom_packet; //Empty buffer, so same packet pointed
        pthread_mutex_unlock(&top_buffer_lock);//Unlocking the top buffer pointer
        //printf("\n\n!!! Empty buffer !!!\n");
    } else { //Else, the buffer is not empty, so we just add the packet at the bottom
        last_bottom_packet->next_packet = bottom_packet;
    }
    pthread_mutex_unlock(&bot_buffer_lock); //unlock the bottom packet

    return;
}

/**
 * Thread to process packets in buffer
 */
void process_buffer(void){
    //Looping through buffer (test)
    struct packet_buffer* tmp_packet; //Initializing iterator
    while(1){
        while(top_packet != NULL) {//Running through buffer
            if(top_packet != bottom_packet || closing == 1){
                pthread_mutex_lock(&top_buffer_lock);

                if(top_packet != NULL){//We have to check if the pointer is still not NULL after locking it
                    tmp_packet = top_packet;
                    if(top_packet->next_packet == NULL){
                        top_packet = NULL;
                        pthread_mutex_lock(&bot_buffer_lock);//Locking bottom packet before changing it
                        bottom_packet = NULL;
                        pthread_mutex_unlock(&bot_buffer_lock);
                    } else {
                        top_packet = top_packet->next_packet; //We swap the pointers early to prevent multiples threads from reading the same packet
                    }
                    pthread_mutex_unlock(&top_buffer_lock);

                    if(DISPLAY_INFOS != 0) printf("\n %03lu", tmp_packet->number);

                    u_long packet_id = insert_packet(tmp_packet);

                    if(packet_id!=0){//If no error while inserting the packet in database
                        process_ethernet(packet_id, (struct packet_buffer*) tmp_packet);
                    }

                    free(tmp_packet->header); //Freeing data from header
                    free(tmp_packet->packet); //Freeing data from captured packet
                    free(tmp_packet); // Freeing structure of buffer
                } else {
                    pthread_mutex_unlock(&bot_buffer_lock);
                    pthread_mutex_unlock(&top_buffer_lock);
                }
            }
        }
        usleep(500);
        if(closing==1 && top_packet == NULL){
            return;
        }
    }
    return;
}


/**
 * This function insert the basic packet informations in the database
 * @param tmp_packet
 * @return sql last id
 */
u_long insert_packet(struct packet_buffer * tmp_packet){
    char * query = (char*) malloc(205);
    sprintf(query,
        "INSERT INTO packet (session_id,next_header,packet_number,packet_time,packet_utime,packet_caplen,packet_len) VALUES (%u,%u,%lu,%u,%u,%u,%u);",
        session_id,
        1,
        tmp_packet->number,
        (u_int) tmp_packet->header->ts.tv_sec,
        (u_int) tmp_packet->header->ts.tv_usec,
        tmp_packet->header->caplen,
        tmp_packet->header->len
    );
    pthread_mutex_lock(&db_lock);
    if(mysql_query(db, query) != 0){
        printf("\nError during query: %s\nCode %u: %s\n", query, mysql_errno(db), mysql_error(db));
        exit(EXIT_FAILURE);
        return 0;
    }
    //mysql_commit(db);
    pthread_mutex_unlock(&db_lock);
    free(query);
    return mysql_insert_id(db);
}

char * gettime(void){
    time_t rawtime;
    char * buffer=malloc(25);
    time(&rawtime);
    strftime(buffer,25,"%Y-%m-%d %H:%M:%S",localtime(&rawtime));
    return buffer;
}
