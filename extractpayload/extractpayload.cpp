// extractpayload.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <string>
#include "pcap.h"

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
typedef struct ethernet_header {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
} eth_hdr_t;

/* IP header */
typedef struct ip_header {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
} ip_hdr_t;
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* UDP header*/
typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
} udp_hdr_t;

/*
* RTP data header
*/
typedef struct {
#if REG_DWORD == REG_DWORD_BIG_ENDIAN
    unsigned int version : 2;   /* protocol version */
    unsigned int p : 1;         /* padding flag */
    unsigned int x : 1;         /* header extension flag */
    unsigned int cc : 4;        /* CSRC count */
    unsigned int m : 1;         /* marker bit */
    unsigned int pt : 7;        /* payload type */
#elif REG_DWORD == REG_DWORD_LITTLE_ENDIAN
    unsigned int cc : 4;        /* CSRC count */
    unsigned int x : 1;         /* header extension flag */
    unsigned int p : 1;         /* padding flag */
    unsigned int version : 2;   /* protocol version */
    unsigned int pt : 7;        /* payload type */
    unsigned int m : 1;         /* marker bit */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif
    unsigned int seq : 16;      /* sequence number */
    uint32_t ts;               /* timestamp */
    uint32_t ssrc;             /* synchronization source */
    uint32_t csrc[1];          /* optional CSRC list */
} rtp_hdr_t;

int parsertp(const u_char* packetdata, int packetsize, int payloadid, FILE* fd1, FILE* fd2) {
    rtp_hdr_t* rtph = (rtp_hdr_t*)packetdata;
    int len = 0;
    if (rtph->version == 2) {
        len = 12 + 4 * rtph->cc;
        if (payloadid == rtph->pt) { // match payload type
            // do something
            const u_char* payload = packetdata + len;
            if (fd1) {
                fwrite(payload, 1, packetsize - len, fd1);
            }
        }
        if (payloadid+1 == rtph->pt) { // match payload type
            // do something
            const u_char* payload = packetdata + len;
            if (fd2) {
                fwrite(payload, 1, packetsize - len, fd2);
            }
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    std::string infile;
    std::string outfile;
    std::string srcport;
    std::string datapayload;
    char errbuf[PCAP_ERRBUF_SIZE];

    for (int i = 1; i < argc; i++) {
        if ((argv[i][1] == 'i') || (argv[i][1] == '-' && stricmp(argv[i]+2, "inputfile") == 0)) {
            infile = argv[++i];
        }
        if ((argv[i][1] == 'o') || (argv[i][1] == '-' && stricmp(argv[i] + 2, "outputfile") == 0)) {
            infile = argv[++i];
        }
        if ((argv[i][1] == 'p') || (argv[i][1] == '-' && stricmp(argv[i] + 2, "sourceport") == 0)) {
            srcport = argv[++i];
        }
        if ((argv[i][1] == 'd') || (argv[i][1] == '-' && stricmp(argv[i] + 2, "datapayload") == 0)) {
            datapayload = argv[++i];
        }
    }
    int isrcport = atoi(srcport.c_str());
    int idatapayload = atoi(datapayload.c_str());

    FILE* fd1 = fopen((outfile + ".h264").c_str(), "wb");
    FILE* fd2 = fopen((outfile + ".opus").c_str(), "wb");

    pcap_t* pcap = pcap_open_offline(infile.c_str(), errbuf);
    pcap_pkthdr* header;
    const u_char* data;
    while (pcap_next_ex(pcap, &header, &data))
    {
        eth_hdr_t* eh = (eth_hdr_t*)data;
        if (header->caplen == header->len) {
            if (ntohs(eh->ether_type) == 0x0800) { // IP
                ip_hdr_t* iph = (ip_hdr_t*)(data + sizeof(eth_hdr_t));
                int size_ip = IP_HL(iph) * 4;
                if (iph->ip_p == 0x11) { //UDP
                    udp_hdr_t* uh = (udp_hdr_t*)(data + sizeof(eth_hdr_t) + size_ip);
                    if (isrcport == ntohs(uh->sport)) { // match the source port
                        // do something
                        parsertp(data + sizeof(eth_hdr_t) + size_ip + sizeof(udp_hdr_t), header->len - sizeof(eth_hdr_t) + size_ip + sizeof(udp_hdr_t), idatapayload, fd1, fd2);
                    }
                }
            }
        }
    }
    fclose(fd1);
    fclose(fd2);
    return 0;
}

