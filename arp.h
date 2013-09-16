/*
 * File:   ipv4.h
 * Author: nav6
 *
 * Created on March 21, 2011, 3:50 PM
 */

/* IP header */

struct layer_arp {
    u_short hdw_type; /* 16 bits */
    u_short proto_type; /* 16 bits */
    u_char  hdw_addr_len; /* 8 bits */
    u_char  proto_addr_len; /* 8 bits */
    u_short operation; /* 16 bits */
    u_char  sender_hdw_addr[6]; /* 48 bits (6 bytes) */
    u_char  sender_proto_addr[4]; /* 32 bits (4 bytes) */
    u_char  target_hdw_addr[6]; /* 48 bits (6 bytes) */
    u_char  target_proto_addr[4]; /* 32 bits (4 bytes) */
};

/* *
 *
 * This function parse the data from the raw packet to a structure in memory
 * to facilitate data manipulation with custom types (less than one byte vars)
 *
 * In this case (ARP), the structure can be casted directly in memory.
 *
 * */
struct layer_arp* parse_arp(const u_char *packet) {
    struct layer_arp* packet_arp=(struct layer_arp*) malloc(sizeof(struct layer_arp));//Size of structure
    packet_arp->hdw_type = ntohs((*(u_short*) packet));
    packet_arp->proto_type = ntohs((*(u_short*) (packet + 2)));
    packet_arp->hdw_addr_len = (*(u_char*) (packet + 4));
    packet_arp->proto_addr_len = (*(u_char*) (packet + 5));
    packet_arp->operation = ntohs((*(u_short*) (packet + 6)));
    packet_arp->sender_hdw_addr[0] = (*(u_char*) (packet + 8));
    packet_arp->sender_hdw_addr[1] = (*(u_char*) (packet + 9));
    packet_arp->sender_hdw_addr[2] = (*(u_char*) (packet + 10));
    packet_arp->sender_hdw_addr[3] = (*(u_char*) (packet + 11));
    packet_arp->sender_hdw_addr[4] = (*(u_char*) (packet + 12));
    packet_arp->sender_hdw_addr[5] = (*(u_char*) (packet + 13));
    packet_arp->sender_proto_addr[0] = (*(u_char*) (packet + 14));
    packet_arp->sender_proto_addr[1] = (*(u_char*) (packet + 15));
    packet_arp->sender_proto_addr[2] = (*(u_char*) (packet + 16));
    packet_arp->sender_proto_addr[3] = (*(u_char*) (packet + 17));
    packet_arp->target_hdw_addr[0] = (*(u_char*) (packet + 18));
    packet_arp->target_hdw_addr[1] = (*(u_char*) (packet + 19));
    packet_arp->target_hdw_addr[2] = (*(u_char*) (packet + 20));
    packet_arp->target_hdw_addr[3] = (*(u_char*) (packet + 21));
    packet_arp->target_hdw_addr[4] = (*(u_char*) (packet + 22));
    packet_arp->target_hdw_addr[5] = (*(u_char*) (packet + 23));
    packet_arp->target_proto_addr[0] = (*(u_char*) (packet + 24));
    packet_arp->target_proto_addr[1] = (*(u_char*) (packet + 25));
    packet_arp->target_proto_addr[2] = (*(u_char*) (packet + 26));
    packet_arp->target_proto_addr[3] = (*(u_char*) (packet + 27));
    return packet_arp;
}


void insert_arp(u_long packet_id, struct layer_arp * packet_arp);


void process_arp(u_long packet_id, const u_char* packet) {
    struct layer_arp* packet_arp=parse_arp(packet);

    if(packet_arp->hdw_type != 1 || packet_arp->proto_type != 0x0800){ //(IPv4)
        printf("  Error: ARP Harware type = %u, Protocol = 0x%04x - Inetmon doesn't support theses protocols", packet_arp->hdw_type, packet_arp->proto_type);
        free(packet_arp);
        packet_arp=NULL;
        return;
    }

    if(DISPLAY_INFOS != 0){
        /* print source and destination IP addresses */
        char *dst = (char *) malloc(50 * sizeof(char));
        printf("  %-25s", inet_ntop(AF_INET, (const void*) &packet_arp->sender_proto_addr, dst, INET_ADDRSTRLEN));
        printf("  %-25s", inet_ntop(AF_INET, (const void*) &packet_arp->target_proto_addr, dst, INET_ADDRSTRLEN));
        free(dst);
        dst=NULL;

        /* determine protocol */
        printf("  IPv4 (0x%04x)", packet_arp->proto_type);

        printf("  Operation : %u ", packet_arp->operation);
        switch(packet_arp->operation){
            case 1:
                printf("REQUEST");
                break;
            case 2:
                printf("REPLY");
                break;
            case 3:
                printf("REQUEST Reverse");
                break;
            case 4:
                printf("REPLY Reverse");
                break;
            default:
                printf("Other");
                break;
        }
    }

    insert_arp(packet_id, packet_arp);

    free(packet_arp);
    packet_arp=NULL;
    return;
}


void insert_arp(u_long packet_id, struct layer_arp * packet_arp){
    char * query = (char*) malloc(320);
    sprintf(query,
        "INSERT INTO proto_4(packet_id,arp_hdw_type,arp_proto_type,arp_hdw_addr_len,arp_proto_addr_len,arp_operation,arp_sender_hdw_addr,arp_sender_proto_addr,arp_target_hdw_addr,arp_target_proto_addr)VALUES(%lu,%hu,%hu,%hu,%hu,%hu,X'%02x%02x%02x%02x%02x%02x',X'%02x%02x%02x%02x',X'%02x%02x%02x%02x%02x%02x',X'%02x%02x%02x%02x');",
        packet_id,
        packet_arp->hdw_type,
        packet_arp->proto_type,
        packet_arp->hdw_addr_len,
        packet_arp->proto_addr_len,
        packet_arp->operation,
        packet_arp->sender_hdw_addr[0],packet_arp->sender_hdw_addr[1],packet_arp->sender_hdw_addr[2],packet_arp->sender_hdw_addr[3],packet_arp->sender_hdw_addr[4],packet_arp->sender_hdw_addr[5],
        packet_arp->sender_proto_addr[0],packet_arp->sender_proto_addr[1],packet_arp->sender_proto_addr[2],packet_arp->sender_proto_addr[3],
        packet_arp->target_hdw_addr[0],packet_arp->target_hdw_addr[1],packet_arp->target_hdw_addr[2],packet_arp->target_hdw_addr[3],packet_arp->target_hdw_addr[4],packet_arp->target_hdw_addr[5],
        packet_arp->target_proto_addr[0],packet_arp->target_proto_addr[1],packet_arp->target_proto_addr[2],packet_arp->target_proto_addr[3]
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

