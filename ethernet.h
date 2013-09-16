/* 
 * File:   ethernet.h
 * Author: nav6
 *
 * Created on March 21, 2011, 3:49 PM
 */


/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6


/* Ethernet header */
struct layer_ethernet {
    u_char destination[ETHER_ADDR_LEN]; /* destination host address */
    u_char source[ETHER_ADDR_LEN]; /* source host address */
    u_short type; /* WARNING ! The type is stored in Big-Endian */
#define ETH_PUP         0x0200 /* Xerox PARC Universal Packet (PUP) */
#define ETH_PUPT        0x0201 /* Xerox PUP Address Translation */
#define ETH_XNS         0x0600 /* Xerox Network System */
#define ETH_IPV4        0x0800 /* Internet Protocol Version 4 */
#define ETH_X75         0x0801 /* X.75 */
#define ETH_NBS         0x0802 /* NBS */
#define ETH_ECMA        0x0803 /* ECMA */
#define ETH_CHAOSNET    0x0804 /* ChaosNet */
#define ETH_X25         0x0805 /* X.25 */
#define ETH_ARP         0x0806 /* Address Resolution Protocol */
#define ETH_XNSC        0x0807 /* XNS Compatibility */
#define ETH_IEEE8021Q   0x8100 /* IEE 802.1Q */
#define ETH_BERKT       0x1000 /* Berkeley Trailer */
#define ETH_BBNS        0x5208 /* BBN Simnet */
/* A LOT MORE TODO ... */
#define ETH_RARP        0x8035 /* Reverse Address Resolution Protocol */
#define ETH_APPLETALK   0x809B /* AppleTalk */
#define ETH_APPLETARP   0x80F3 /* AppleTalk Address Resolution Protocol */
#define ETH_IPX         0x8137 /* NetWare IPX/SPX */
#define ETH_IPV6        0x86DD /* Internet Protocol Version 6 */
#define ETH_CISCO       0x88BB /* Cisco Systems */
#define ETH_SERCOS3     0x88CD /* Sercos 3 */

};


void insert_ethernet(u_long packet_id, struct layer_ethernet * ethernet, u_int next_header);

void process_ethernet(u_long packet_id, struct packet_buffer* packet) {
    struct layer_ethernet * ethernet = (struct layer_ethernet *) packet->packet;
    if(DISPLAY_INFOS != 0){
        printf("  %02x:%02x:%02x:%02x:%02x:%02x", ethernet->source[0], ethernet->source[1], ethernet->source[2], ethernet->source[3], ethernet->source[4], ethernet->source[5]);
        printf("  %02x:%02x:%02x:%02x:%02x:%02x", ethernet->destination[0], ethernet->destination[1], ethernet->destination[2], ethernet->destination[3], ethernet->destination[4], ethernet->destination[5]);
    }

    u_short proto = ntohs(ethernet->type);

    switch(proto) {
            /* Common protocols */
        case ETH_IPV4:
            insert_ethernet(packet_id, ethernet, 2);//Specific value from database
            if(DISPLAY_INFOS != 0) printf("  IPv4    ");
            process_ipv4(packet_id, (const u_char *)(packet->packet)+ SIZE_ETHERNET);
            return;
        case ETH_IPV6:
            insert_ethernet(packet_id, ethernet, 3);//Specific value from database
            if(DISPLAY_INFOS != 0) printf("  IPv6    ");
            process_ipv6(packet_id, (const u_char *)(packet->packet)+ SIZE_ETHERNET);
            return;
        case ETH_ARP:
            insert_ethernet(packet_id, ethernet, 4);//Specific value from database
            if(DISPLAY_INFOS != 0) printf("  ARP     ");
            process_arp(packet_id, (const u_char *)(packet->packet)+ SIZE_ETHERNET);
            return;

        /* OTHER PROTOCOLS */
        case ETH_RARP://Obsolete
            if(DISPLAY_INFOS != 0) printf("  RARP    ");
            break;
        case ETH_PUP:
            if(DISPLAY_INFOS != 0) printf("  PUP     ");
            break;
        case ETH_PUPT:
            if(DISPLAY_INFOS != 0) printf("  PUP Address Translation");
            break;
        case ETH_XNS:
            if(DISPLAY_INFOS != 0) printf("  XNS     ");
            break;
        case ETH_X75:
            if(DISPLAY_INFOS != 0) printf("  X.75    ");
            break;
        case ETH_NBS:
            if(DISPLAY_INFOS != 0) printf("  NBS     ");
            break;
        case ETH_ECMA:
            if(DISPLAY_INFOS != 0) printf("  ECMA    ");
            break;
        case ETH_CHAOSNET:
            if(DISPLAY_INFOS != 0) printf("  Chaosnet");
            break;
        case ETH_X25:
            if(DISPLAY_INFOS != 0) printf("  X.25    ");
            break;
        case ETH_XNSC:
            if(DISPLAY_INFOS != 0) printf("  XNS Compatibility");
            break;
        case ETH_IEEE8021Q:
            if(DISPLAY_INFOS != 0) printf(" IEEE 802.1Q");
            break;
        case ETH_BERKT:
            if(DISPLAY_INFOS != 0) printf("  Berkeley Trailer");
            break;
        case ETH_BBNS:
            if(DISPLAY_INFOS != 0) printf("  BBN     ");
            break;
        case ETH_APPLETALK:
            if(DISPLAY_INFOS != 0) printf("  AppleTalk");
            break;
        case ETH_APPLETARP:
            if(DISPLAY_INFOS != 0) printf("  AppleTalk ARP");
            break;
        case ETH_IPX:
            if(DISPLAY_INFOS != 0) printf("  IPX/SPX  ");
            break;
        case ETH_CISCO:
            if(DISPLAY_INFOS != 0) printf("  Cisco Sys");
            break;
        case ETH_SERCOS3:
            if(DISPLAY_INFOS != 0) printf("  Sercos 3 ");
            break;
        default:
            if (proto < 0x05dc) {
                if(DISPLAY_INFOS != 0) printf("  IEEE 802.3 (Length %u)", proto);
                break;
            }
            if(DISPLAY_INFOS != 0) printf("  0x%04x   ", proto);
            break;
    }
    insert_ethernet(packet_id, ethernet, 0);//Generic ethernet packet insertion
}

void insert_ethernet(u_long packet_id, struct layer_ethernet * ethernet, u_int next_header){
    char * query = (char*) malloc(205);
    sprintf(query,
        "INSERT INTO proto_1 (packet_id,next_header,eth_dest,eth_src,eth_type) VALUES (%lu,%u,X'%02x%02x%02x%02x%02x%02x',X'%02x%02x%02x%02x%02x%02x',%u);",
        packet_id,
        next_header,
        ethernet->destination[0], ethernet->destination[1], ethernet->destination[2], ethernet->destination[3], ethernet->destination[4], ethernet->destination[5],
        ethernet->source[0], ethernet->source[1], ethernet->source[2], ethernet->source[3], ethernet->source[4], ethernet->source[5],
        (u_int) ntohs(ethernet->type)
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

