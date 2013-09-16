/*
 * File:   tcp.h
 * Author: nav6
 *
 * Created on March 21, 2011, 3:50 PM
 */

/* IP header */

struct layer_tcp {
    u_short src_port; /* 16 bits */
    u_short dest_port; /* 16 bits */
    u_int seq_num; /* 32 bits */
    u_int ack_num; /* 32 bits */
    u_char data_offset; /* Originally 4 bits */
    u_char reserved; /* Originally 4 bits */
    u_char flags; /* 8 bits */
    u_short window_size; /* 16 bits */
    u_short checksum; /* 16 bits */
    u_short urgent_pointer; /* 16 bits */
};

/* *
 *
 * This function parse the data from the raw packet to a structure in memory
 * to facilitate data manipulation with custom types (less than one byte vars)
 *
 * */
struct layer_tcp* parse_tcp(const u_char *packet) {
    struct layer_tcp* packet_tcp=(struct layer_tcp*)malloc(sizeof(struct layer_tcp));//Size of structure
    packet_tcp->src_port = ntohs(*(u_short*) packet);
    packet_tcp->dest_port = ntohs(*(u_short*) (packet + 2));
    packet_tcp->seq_num = ntohl(*(u_int*) (packet + 4));
    packet_tcp->ack_num = ntohl(*(u_int*) (packet + 8));
    packet_tcp->data_offset = (*(u_char*) (packet + 12) >> 4);
    packet_tcp->reserved = (*(u_char*) (packet + 12)) & 0x0f;
    packet_tcp->flags = (*(u_char*) (packet + 13));
    packet_tcp->window_size = ntohs(*(u_short*) (packet + 14));
    packet_tcp->checksum = ntohs(*(u_short*) (packet + 16));
    packet_tcp->urgent_pointer = ntohs(*(u_short*) (packet + 18));
    return packet_tcp;
}


void insert_tcp(u_long packet_id, struct layer_tcp * packet_tcp, u_int next_header);


void process_tcp(u_long packet_id, const u_char* packet) {
    struct layer_tcp* packet_tcp=parse_tcp(packet);

    /* print source and destination IP addresses */
    if(DISPLAY_INFOS != 0){
        printf("  Src port: %u - Dest port: %u",packet_tcp->src_port,packet_tcp->dest_port);
    }

    insert_tcp(packet_id,packet_tcp,0);
    
    free(packet_tcp);
    packet_tcp=NULL;
}


void insert_tcp(u_long packet_id, struct layer_tcp * packet_tcp, u_int next_header){
    char * query = (char*) malloc(320);
    sprintf(query,
        "INSERT INTO proto_5 (packet_id,next_header,tcp_src_port,tcp_dest_port,tcp_seq_num,tcp_ack_num,tcp_data_offset,tcp_reserved,tcp_flags,tcp_window_size,tcp_checksum,tcp_urgent_pointer)VALUES(%lu,%u,%hu,%hu,%u,%u,%hu,%hu,%hu,%hu,%hu,%hu);",
        packet_id,
        next_header,
        packet_tcp->src_port,
        packet_tcp->dest_port,
        packet_tcp->seq_num,
        packet_tcp->ack_num,
        packet_tcp->data_offset,
        packet_tcp->reserved,
        packet_tcp->flags,
        packet_tcp->window_size,
        packet_tcp->checksum,
        packet_tcp->urgent_pointer
    );
    pthread_mutex_lock(&db_lock);
    if(mysql_query(db, query) != 0){
        printf("\nError during query: %s\nCode %u: %s\n", query, mysql_errno(db), mysql_error(db));
        exit(EXIT_FAILURE);
    }
    //mysql_commit(db);
    pthread_mutex_unlock(&db_lock);
    free(query);
}

