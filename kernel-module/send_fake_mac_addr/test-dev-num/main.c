#include <pcap.h>
#include <libnet.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-structures.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

// const char *buf =
//     "GET / HTTP/1.1\r\n"
//     "Host: shidou.com\r\n"
//     "Connection: keep-alive\r\n"
//     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
//     "Upgrade-Insecure-Requests: 1\r\n"
//     "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/600.1.3 (KHTML, like Gecko) Version/8.0 Mobile/12A4345d Safari/600.1.4\r\n"
//     "Accept-Encoding: gzip, deflate, sdch\r\n"
//     "Accept-Language: en-US,en;q=0.8,zh-TW;q=0.6,zh;q=0.4\r\n"
//     "\r\n";
char* dev0 = "wlan0";
 
// u_char enet_src[6] = {0x0d, 0x0e, 0x0a, 0x0d, 0x00, 0x00};
// 40:16:9f:83:a8:8e
u_char enet_src[6] = {0x40, 0x16, 0x9f, 0x83, 0xa8, 0x8e};
unsigned char enet_dst[6] = {0xc0, 0x61, 0x18, 0xfb, 0xe2, 0x00};
// unsigned char enet_dst[6] = {0x00, 0xe0, 0x66, 0xc3, 0x63, 0x74};
// 00:e0:66:c3:63:74
// c0:61:18:fb:e2:00

int send_packet(char* dev, unsigned char* enet_src, unsigned char* enet_dst,
                unsigned int saddr, unsigned int daddr,
                unsigned short sport, unsigned short dport, unsigned int seq, unsigned int ack,
                unsigned char* payload, unsigned short payload_len, unsigned char tcp_flag) {

    int packet_size = 14 + 20 + 20 + payload_len;
    int ip_size = 20 + 20 + payload_len;
    int tcp_size = 20 + payload_len;
    unsigned char* packet = NULL;/* pointer to our packet buffer */
    int c = 0, tag = 0;

    char errbuf[LIBNET_ERRBUF_SIZE];   /* error buffer */
    libnet_t *network;   /* pointer to link interface struct */


    /*
     *  Step 1: Network Initialization (interchangable with step 2).
     */
    if ((network = (libnet_t *)libnet_init(LIBNET_LINK, dev, errbuf)) == NULL) {
        printf("libnet_open_link_interface: %s\n", errbuf);
    }



    /*tag = */libnet_build_tcp(
            sport,                /* source TCP port */
            dport,                /* destination TCP port */
            seq,                /* sequence number */
            ack,                   /* acknowledgement number */
            tcp_flag,                 /* control flags */
            4096,                   /* window size */
            0,                      /* checksum */
            0,                      /* urgent pointer */
            20 + payload_len, /* total len of TCP packet*/
            payload,                   /* payload (none) */
            payload_len,                      /* payload length */
            network,
            0);
    printf("libnet error: %s\n", libnet_geterror(network));


    libnet_build_ipv4(
            20 + 20 + payload_len,
            0,                      /* IP tos */
            0,                     /* IP ID */
            0,                      /* Frag */
            64,                    /* TTL */
            IPPROTO_TCP,            /* Transport protocol */
            0,              /* checksum */
            saddr,         /* Source IP (little endian)*/
            daddr,         /* Destination IP  (little endian)*/
            NULL,                /* Pointer to payload */
            0,
            network,
            0); /* Packet header memory */

    printf("libnet error: %s\n", libnet_geterror(network));
    libnet_build_ethernet(
            enet_dst,
            enet_src,
            ETHERTYPE_IP,
            NULL,
            0,
            network,
            0);

    printf("libnet error: %s\n", libnet_geterror(network));


    c = libnet_write(network);
    printf("libnet error: %s\n", libnet_geterror(network));
    printf("before write to NIC through libnet----->%d == %d.\n", packet_size, c);
    if (c < packet_size) {
        printf("libnet_write only wrote %d bytes\n", c);
    }


    /*
     *  Free packet memory.
     */
    libnet_destroy(network);
    printf("\n");
}

 


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("send-packets dst src\n");
        exit(0);
    }

    struct in_addr dst;
    struct in_addr src;
    inet_aton(argv[1], &dst); 
    inet_aton(argv[2], &src);

   while(1){
        enet_src[5]++;
        send_packet(dev0, enet_src, enet_dst,
                              src.s_addr, dst.s_addr, 
                              htons(12345), htons(80), htonl(0), htonl(0),
                              NULL, 0, 0x02);

        printf("send: %x\n", enet_src[5]);
        sleep(1);
	}

   return(0);
}

