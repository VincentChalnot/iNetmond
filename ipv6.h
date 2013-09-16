/* 
 * File:   ipv6.h
 * Author: nav6
 *
 * Created on March 21, 2011, 3:50 PM
 */

/* IP header */
#define SIZE_IPV6 320 //Warning, not the size of the structure !

struct layer_ipv6 {
    u_char version; /* Originally 4 bits */
    u_char traffic_class; /* 8 bits */
    u_int flow_label; /* Originally 20 bits */
    u_short payload_length; /* 16 bits */
    u_char next_header; /* 8 bits */
    u_char hop_limit; /* 8 bits */
    u_short source[8]; /* 128 bits */
    u_short destination[8]; /* 128 bits */
};

struct layer_ipv6* parse_ipv6(const u_char* packet){
    struct layer_ipv6* packet_ipv6 = (struct layer_ipv6*) malloc(sizeof(struct layer_ipv6));//Size of structure
    packet_ipv6->version = (*(u_char*) packet) >> 4; // We take the first byte and remove the header length of 4 bits
    packet_ipv6->traffic_class = ntohs((u_short)((*(u_int*) packet) >> 4));
    packet_ipv6->flow_label = ntohl((*(u_int*) packet) & 0x000fffff);
    packet_ipv6->payload_length = ntohs(*(u_short*) (packet + 4));
    packet_ipv6->next_header = *(u_char*) (packet + 6);
    packet_ipv6->hop_limit = *(u_char*) (packet + 7);
    packet_ipv6->source[0] = ntohs(*(u_short*) (packet + 8));
    packet_ipv6->source[1] = ntohs(*(u_short*) (packet + 10));
    packet_ipv6->source[2] = ntohs(*(u_short*) (packet + 12));
    packet_ipv6->source[3] = ntohs(*(u_short*) (packet + 14));
    packet_ipv6->source[4] = ntohs(*(u_short*) (packet + 16));
    packet_ipv6->source[5] = ntohs(*(u_short*) (packet + 18));
    packet_ipv6->source[6] = ntohs(*(u_short*) (packet + 20));
    packet_ipv6->source[7] = ntohs(*(u_short*) (packet + 22));
    packet_ipv6->destination[0] = ntohs(*(u_short*) (packet + 24));
    packet_ipv6->destination[1] = ntohs(*(u_short*) (packet + 26));
    packet_ipv6->destination[2] = ntohs(*(u_short*) (packet + 28));
    packet_ipv6->destination[3] = ntohs(*(u_short*) (packet + 30));
    packet_ipv6->destination[4] = ntohs(*(u_short*) (packet + 32));
    packet_ipv6->destination[5] = ntohs(*(u_short*) (packet + 34));
    packet_ipv6->destination[6] = ntohs(*(u_short*) (packet + 36));
    packet_ipv6->destination[7] = ntohs(*(u_short*) (packet + 38));
    return packet_ipv6;
}

void insert_ipv6(u_long packet_id, struct layer_ipv6 * packet_ipv6, u_int next_header);

void process_ipv6(u_long packet_id, const u_char *packet) {
    struct layer_ipv6* packet_ipv6=parse_ipv6(packet);//Size of structure

    if(DISPLAY_INFOS != 0){
        /* print source and destination IP addresses */
        char *dst = (char *) malloc(30 * sizeof(char));
        printf("  %-25s", inet_ntop(AF_INET6, (const void*) (packet+8), dst, INET6_ADDRSTRLEN));
        printf("  %-25s", inet_ntop(AF_INET6, (const void*) (packet+24), dst, INET6_ADDRSTRLEN));
        free(dst);
        dst=NULL;

        /* determine protocol */
        printf("  %-20s", IP_PROTOS[packet_ipv6->next_header]);
    }
    
    switch (packet_ipv6->next_header) {
        case IPPROTO_TCP:
            insert_ipv6(packet_id,packet_ipv6,5);
            process_tcp(packet_id,(const u_char *)(packet + SIZE_IPV6));
            break;
        case IPPROTO_UDP:
            insert_ipv6(packet_id,packet_ipv6,6);
            break;
        case IPPROTO_ICMP:
            insert_ipv6(packet_id,packet_ipv6,0);
            break;
        case IPPROTO_IP:
            insert_ipv6(packet_id,packet_ipv6,0);
            break;
        default:
            insert_ipv6(packet_id,packet_ipv6,0);
            break;
    }
    free(packet_ipv6);
    packet_ipv6=NULL;
}

void insert_ipv6(u_long packet_id, struct layer_ipv6 * packet_ipv6, u_int next_header){
    char * query = (char*) malloc(320);
    sprintf(query,
        "INSERT INTO proto_3(packet_id,next_header,ipv6_version,ipv6_traffic_class,ipv6_flow_label,ipv6_payload_length,ipv6_next_header,ipv6_hop_limit,ipv6_src_addr,ipv6_dest_addr)VALUES(%lu,%u,%hu,%hu,%u,%hu,%hu,%hu,X'%04x%04x%04x%04x%04x%04x%04x%04x',X'%04x%04x%04x%04x%04x%04x%04x%04x');",
        packet_id,
        next_header,
        packet_ipv6->version,
        packet_ipv6->traffic_class,
        packet_ipv6->flow_label,
        packet_ipv6->payload_length,
        packet_ipv6->next_header,
        packet_ipv6->hop_limit,
        packet_ipv6->source[0], packet_ipv6->source[1], packet_ipv6->source[2], packet_ipv6->source[3], packet_ipv6->source[4], packet_ipv6->source[5], packet_ipv6->source[6], packet_ipv6->source[7],
        packet_ipv6->destination[0], packet_ipv6->destination[1], packet_ipv6->destination[2], packet_ipv6->destination[3], packet_ipv6->destination[4], packet_ipv6->destination[5], packet_ipv6->destination[6], packet_ipv6->destination[7]
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
