/* 
 * File:   ipv4.h
 * Author: nav6
 *
 * Created on March 21, 2011, 3:50 PM
 */

/* IP header */

struct layer_ipv4 {
    u_char version; /* Originally 4 bits */
    u_char header_len; /* Originally 4 bits */
    u_char service; /* Originally 6 bits */
    u_short length; /* 16 bits */
    u_short identification; /* 16 bits */
    u_char flags; /* Originally 3 bits */
    u_short offset; /* Originally 13 bits */
    u_char ttl; /* 8 bits */
    u_char protocol; /* 8 bits */
    u_short checksum; /* 16 bits */
    u_char source[4]; /* 32 bits */
    u_char destination[4]; /* 32 bits */
};

/* *
 *
 * This function parse the data from the raw packet to a structure in memory
 * to facilitate data manipulation with custom types (less than one byte vars)
 *
 * */
struct layer_ipv4* parse_ipv4(const u_char *packet) {
    struct layer_ipv4* packet_ipv4=(struct layer_ipv4*)malloc(sizeof(struct layer_ipv4));//Size of structure
    packet_ipv4->version = (*(u_char*) packet) >> 4; // We take the first byte and remove the header length of 4 bits
    packet_ipv4->header_len = (*(u_char*) packet) & 0x0f; // Just removing the firsts 4 bits
    packet_ipv4->service = (*(u_char*) (packet + 1)); // We take the second byte and remove the explicit congestion notification of 2 bits
    packet_ipv4->length = ntohs(*(u_short*) (packet + 2));
    packet_ipv4->identification = ntohs(*(u_short*) (packet + 4));
    packet_ipv4->flags = (*(u_char*) (packet + 6)) >> 5;
    packet_ipv4->offset = ntohs((*(u_short*) (packet + 6)) & 0x1f);
    packet_ipv4->ttl = *(u_char*) (packet + 8);
    packet_ipv4->protocol = *(u_char*) (packet + 9);
    packet_ipv4->checksum = ntohs(*(u_short*) (packet + 10));
    packet_ipv4->source[0] = *(u_char*) (packet + 12);
    packet_ipv4->source[1] = *(u_char*) (packet + 13);
    packet_ipv4->source[2] = *(u_char*) (packet + 14);
    packet_ipv4->source[3] = *(u_char*) (packet + 15);
    packet_ipv4->destination[0] = *(u_char*) (packet + 16);
    packet_ipv4->destination[1] = *(u_char*) (packet + 17);
    packet_ipv4->destination[2] = *(u_char*) (packet + 18);
    packet_ipv4->destination[3] = *(u_char*) (packet + 19);
    return packet_ipv4;
}


void insert_ipv4(u_long packet_id, struct layer_ipv4 * packet_ipv4, u_int next_header);


void process_ipv4(u_long packet_id, const u_char* packet) {
    struct layer_ipv4* packet_ipv4=parse_ipv4(packet);

    short ip_size = packet_ipv4->header_len * 4; /* Only for 32 bits words systems ? */
    if (ip_size < 20) {
        printf("   * Invalid IP header length: %u bytes", ip_size);
        return;
    }

    /* print source and destination IP addresses */
    if(DISPLAY_INFOS != 0){
        char *dst = (char *) malloc(50 * sizeof(char));
        printf("  %-25s", inet_ntop(AF_INET, (const void*) &packet_ipv4->source, dst, INET_ADDRSTRLEN));
        printf("  %-25s", inet_ntop(AF_INET, (const void*) &packet_ipv4->destination, dst, INET_ADDRSTRLEN));
        free(dst);
        dst=NULL;

        /* determine protocol */
        printf("  %-20s", IP_PROTOS[packet_ipv4->protocol]);
    }

    switch (packet_ipv4->protocol) {
        case IPPROTO_TCP:
            insert_ipv4(packet_id,packet_ipv4,5);
            process_tcp(packet_id,(const u_char *)(packet + ip_size));
            break;
        case IPPROTO_UDP:
            insert_ipv4(packet_id,packet_ipv4,6);
            break;
        case IPPROTO_ICMP:
            insert_ipv4(packet_id,packet_ipv4,0);
            break;
        case IPPROTO_IP:
            insert_ipv4(packet_id,packet_ipv4,0);
            break;
        default:
            insert_ipv4(packet_id,packet_ipv4,0);
            break;
    }
    free(packet_ipv4);
    packet_ipv4=NULL;
}


void insert_ipv4(u_long packet_id, struct layer_ipv4 * packet_ipv4, u_int next_header){
    char * query = (char*) malloc(320);
    sprintf(query,
        "INSERT INTO proto_2(packet_id,next_header,ipv4_version,ipv4_header_length,ipv4_tos,ipv4_total_length,ipv4_id,ipv4_flags,ipv4_frag_offset,ipv4_ttl,ipv4_protocol,ipv4_header_cheksum,ipv4_src_addr,ipv4_dest_addr)VALUES(%lu,%u,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,X'%02x%02x%02x%02x',X'%02x%02x%02x%02x');",
        packet_id,
        next_header,
        packet_ipv4->version,
        packet_ipv4->header_len,
        packet_ipv4->service,
        packet_ipv4->length,
        packet_ipv4->identification,
        packet_ipv4->flags,
        packet_ipv4->offset,
        packet_ipv4->ttl,
        packet_ipv4->protocol,
        packet_ipv4->checksum,
        packet_ipv4->source[0], packet_ipv4->source[1], packet_ipv4->source[2], packet_ipv4->source[3],
        packet_ipv4->destination[0], packet_ipv4->destination[1], packet_ipv4->destination[2], packet_ipv4->destination[3]
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

