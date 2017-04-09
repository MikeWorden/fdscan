#ifndef FSNIFFER_INCLUDED
#define FSNIFFER_INCLUDED
#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_FLOWS 8192
#define MAX_FILE_PATH 256
#define MAX_SCANNERS 1024


struct flow_record {
    char    protocol[4];
    double  start_time;
    char    source_address[16];
    char    destination_address[16];
    u_char  source_port;
    u_char  destination_port;
    u_int   total_packets;
    u_int   total_bytes;
    double  end_time;
    int     in_use;
    char    flags[50];
    char    direction[4];
    int     interactions;
};
struct scanner {
    char    source_address[16];
    char    destination_address[16];
    char    protocol[4];
    char    port_list[1024];
    int    port_count;
    int     host_count;
    
};

struct options {
    char    file_name[MAX_FILE_PATH];
    char    interface_name[50];
    time_t  time_start;
    double  time_offset;
    double  time;
    int     time_set;
    double  time_offset_set;
    int     file;
    int     interface;
    int     num_flow_records;
    int     num_flow_records_set;
    int     flow_timeout;
    struct  flow_record  flow_records[MAX_FLOWS];
    int     hosts_threshold;
    int     ports_threshold;
    int     verbose;
};



typedef struct options Options;




//PCAP Related Defines
//Defines (yuk) -- necessary evil
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LENGTH 1518
//Ethernet packets are always 14 bytes
#define ETHERNET_PACKET_LENGTH 14
// Ethernet address are 6 bytes

//IP Defines
#define ETHERNET_ADDRESS_LENGTH 6
#define IP_RESERVE_FRAGMENT_FLAG  0x8000
#define IP_DONT_FRAGMENT_FLAG 0x4000
#define IP_MORE_FRAGMENTS_FLAG 0x2000
#define IP_FRAMENT_MASK 0x1fff


//TCP Defines
typedef u_int tcp_seq;


struct ethernet_packet {
        u_char ethernet_source[ETHERNET_ADDRESS_LENGTH];
        u_char ethernet_destination[ETHERNET_ADDRESS_LENGTH];
        u_short ethernet_type;
};

struct ip_packet_header {
    u_char  ip_version_header_length;
    u_char  ip_type_of_service;
    u_short ip_length;
    u_short ip_identification;
    u_short ip_offset;
    u_char  ip_time_to_live;
    u_char  ip_protocol;
    u_short ip_checksum;
    struct in_addr ip_source, ip_destination;

};


#define IP_HL(ip_header)               (((ip_header)->ip_version_header_length) & 0x0f)
#define IP_V(ip_header)                (((ip_header)->ip_version_header_length) >> 4)


struct  tcp_packet_header {
        u_short tcp_source_port;
        u_short tcp_destination_port;
        tcp_seq tcp_sequence_number;
        tcp_seq tcp_acknowledgement_number;
        u_char  tcp_data_offset;
        #define TCP_DATA_OFF(tcp_header)      (((tcp_header)->tcp_data_offset & 0xf0) >> 4)
        u_char  tcp_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short tcp_window;
        u_short tcp_checksum;
        u_short tcp_urgent_pointer;
};

struct  udp_packet_header {
        u_short udp_source_port;
        u_short udp_destination_port;
        u_short udp_datagram_length;
        u_short udp_checksum;


};

struct icmp_packet_header
{
        u_int8_t icmp_type;
        u_int8_t icmp_code;
        unsigned int icmp_checksum;
        #define ICMP_ECHOREPLY		0	/* Echo Reply			*/
        #define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
        #define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
        #define ICMP_REDIRECT		5	/* Redirect (change route)	*/
        #define ICMP_ECHO		    8	/* Echo Request			*/
        #define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
        #define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
        #define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
        #define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
        #define ICMP_INFO_REQUEST	15	/* Information Request		*/
        #define ICMP_INFO_REPLY		16	/* Information Reply		*/
        #define ICMP_ADDRESS		17	/* Address Mask Request		*/
        #define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
        #define NR_ICMP_TYPES		18

        /* Codes for UNREACH. */
        #define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
        #define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
        #define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
        #define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
        #define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
        #define ICMP_SR_FAILED		5	/* Source Route failed		*/
        #define ICMP_NET_UNKNOWN	6
        #define ICMP_HOST_UNKNOWN	7
        #define ICMP_HOST_ISOLATED	8
        #define ICMP_NET_ANO		9
        #define ICMP_HOST_ANO		10
        #define ICMP_NET_UNR_TOS	11
        #define ICMP_HOST_UNR_TOS	12
        #define ICMP_PKT_FILTERED	13	/* Packet filtered */
        #define ICMP_PREC_VIOLATION	14	/* Precedence violation */
        #define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
        #define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

        /* Codes for REDIRECT. */
        #define ICMP_REDIR_NET		0	/* Redirect Net			*/
        #define ICMP_REDIR_HOST		1	/* Redirect Host		*/
        #define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
        #define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

        /* Codes for TIME_EXCEEDED. */
        #define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
        #define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

};



void Usage();
int Get_Options(int argc, char ** argv, Options *Opt );
void Print_Options (Options *opts);
int Check_Interface(Options *Opt);
int Check_File(Options *Opt);
int Open_File(Options *Opt);
int Open_Interface(Options *Opt);
const char * print_tcp_flags(u_char flags);
void print_flows(Options *opts, int purge_buffer);
void print_scans(Options *Opt, int purge_buffer);
void print_scans_verbose(Options *Opt, int purge_buffer);

//void process_packet(u_char *args, const struct pcap_pkthdr *header);

#endif // FSNIFFER_INCLUDED
