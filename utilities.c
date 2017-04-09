 /*
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * This homework "sniffer.c" and "utilities.c" are derivative works of "sniffer.c" and is
 *  covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 *
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 *
 ****************************************************************************/



#include <pcap.h>
#include "./fdscan.h"

/******************************************************************************
* Usage:  Print out command-line options
*
******************************************************************************/
void Usage() {
  printf("fdscan [-r filename] [-i interface] [-t time] [-o time_offset]  [-S secs] [-h HNum] [-p PNum] [-V]\n");
}


/******************************************************************************
* Check_Interface:  Checks that a valid interface has been provided
*
******************************************************************************/

int Check_Interface(Options *Opt)  {

    char  errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    if (strlen(Opt->interface_name) > 0) {
        handle = pcap_open_live(Opt->interface_name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", Opt->interface_name, errbuf);
            return(2);
        }
        pcap_close(handle);
    }
    return 0;
}

/******************************************************************************
* Check_File:  Checks that a valid file has been provided.  Uses the pcap_open_offline
*              function to validate it's an actual pcap file
*
******************************************************************************/

int Check_File(Options *Opt) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    if (strlen(Opt->file_name) > 0 )  {
        handle = pcap_open_offline(Opt->file_name, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open offline file:  %s: %s\n", Opt->file_name, errbuf);
            return (2);
        }
    pcap_close(handle);
    }
    return 0;
}

/******************************************************************************
* Get Options:  Overuse of getopts to handle options and plunk them into
*               an Options struct for use throughout the program
******************************************************************************/

int Get_Options(int argc, char ** argv, Options *Opt )  {

    int c;

    memset(Opt->file_name,0,sizeof Opt->file_name);
    memset(Opt->interface_name,0,sizeof Opt->interface_name);
    Opt->time=0;
    Opt->time_set = 0;
    Opt->time_start = 0.0;
    Opt->time_offset = 0.0;
    Opt->time_offset_set = 0;
    Opt->file = 0;
    Opt->interface = 0;
    Opt->num_flow_records = 0;
    Opt->num_flow_records_set = 0;
    Opt->flow_timeout = 60;
    Opt->hosts_threshold = 65;
    Opt->ports_threshold = 25;
    Opt->verbose = 0;
    

    
    
    //  Could have initialized via {var1, var2...} but this is clearer
    for (int i=0; i<MAX_FLOWS; i++ ) {
        strncpy(Opt->flow_records[i].destination_address, "", sizeof(Opt->flow_records[i].destination_address));
        Opt->flow_records[i].destination_port = 0;
        Opt->flow_records[i].end_time=0;
        strncpy(Opt->flow_records[i].source_address, "", sizeof(Opt->flow_records[i].source_address));
        Opt->flow_records[i].source_port=0;
        Opt->flow_records[i].start_time=0;
        Opt->flow_records[i].total_bytes =0;
        Opt->flow_records[i].total_packets=0;
        Opt->flow_records[i].in_use = 0;
        strncpy(Opt->flow_records[i].flags, "", sizeof(Opt->flow_records[i].flags));
        strncpy(Opt->flow_records[i].direction, "", sizeof(Opt->flow_records[i].direction));
        Opt->flow_records[i].interactions = 0;
        
        
    }
    
    
    
    opterr = 0;
    if (argc <= 2) {
        Usage();
        return 1;
    }

    while ((c = getopt (argc, argv, "r: i: t: o: S: h: p: V")) != -1)
    {
        switch (c)
        {
            case 'r':
                strncpy(Opt->file_name, optarg, sizeof Opt->file_name - 1);
                Opt->file = 1;
                break;
            case 'i':
                strncpy(Opt->interface_name, optarg, sizeof Opt->interface_name - 1);
                Opt->interface = 1;
                Opt->time_start = time(NULL);
                break;
            case 't':
                Opt->time = strtod(optarg, NULL);
                Opt->time_set = 1;
                break;
            case 'o':
                Opt->time_offset = strtod(optarg, NULL);
                Opt->time_offset_set = 1;
                break;
            case 'S':
                Opt->flow_timeout = (int)strtol(optarg, NULL, 10);
                break;
            case 'h':
                Opt->hosts_threshold = (int)strtol(optarg, NULL, 10);
                break;
            case 'p':
                Opt->ports_threshold = (int)strtol(optarg, NULL, 10);
                break;
            case 'V':
                Opt->verbose = 1;
                
            case '?':
                if ((optopt == 'r') || (optopt =='i'))
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                             "Unknown option character `\\x%x'.\n",
                             optopt);
                return 1;
            default:
                return -1;
        }
    }
    


    if ((strlen(Opt->file_name) >0 ) & (strlen(Opt->interface_name) >0) ) {
        fprintf(stderr, "Invalid option:  you can use -r or -i, but not both\n");
        return 1;
    }

    if (( Check_Interface( Opt) != 0) || (Check_File(Opt) != 0) ) {
        fprintf(stderr, "Invalid PCAP device or file\n");
        return 1;
    }

    return 0;
}

/******************************************************************************
* Get_TCP_Flags:  Return a string of flags, given the flag portion of a TCP header
*
******************************************************************************/

void get_tcp_flags(char *flag_string, int flag_size, u_char flags) {


    memset(flag_string,0,flag_size);

    if ( flags & TH_ACK ) {
        strncat(flag_string, "ACK ", flag_size);
    }
    if ( flags & TH_FIN ) {
        strncat(flag_string, "FIN ", flag_size);
    }
    if ( flags & TH_SYN ) {
        strncat(flag_string, "SYN ", flag_size);
    }
    if ( flags & TH_RST ) {
        strncat(flag_string, "RST ", flag_size);
    }
    if ( flags & TH_PUSH ) {
        strncat(flag_string, "PUSH ", flag_size);
    }
    if ( flags & TH_URG ) {
        strncat(flag_string, "URG ", flag_size);
    }
    if ( flags & TH_ECE ) {
        strncat(flag_string, "ECE ", flag_size);
    }
    if ( flags & TH_CWR ) {
        strncat(flag_string, "CWR ", flag_size);
    }
    


}

/******************************************************************************
* get_icmp_unreachable_codes:  Return any codes if the icmp message type is
*                              unreachable
*
******************************************************************************/

void get_icmp_unreachable_codes(char *flag_string, int flag_size, u_char icmp_code) {
    memset(flag_string, 0, flag_size);

    if ( icmp_code == ICMP_NET_UNREACH ) {
        strncat(flag_string, "Net Unreachable ", flag_size);
    }
    if ( icmp_code == ICMP_HOST_UNREACH ) {
        strncat(flag_string, "Host Unreachable ", flag_size);
    }
    if ( icmp_code == ICMP_PROT_UNREACH ) {
        strncat(flag_string, "Protocol Unreachable ", flag_size);
    }
    if ( icmp_code == ICMP_FRAG_NEEDED ) {
        strncat(flag_string, "Fragmentation Needed ", flag_size);
    }
    if ( icmp_code == ICMP_SR_FAILED ) {
        strncat(flag_string, "Source Route Failed ", flag_size);
    }
    if ( icmp_code == ICMP_NET_UNKNOWN ) {
        strncat(flag_string, "Net Unknown ", flag_size);
    }
    if ( icmp_code == ICMP_HOST_UNKNOWN ) {
        strncat(flag_string, "Host Unknown ", flag_size);
    }
    if ( icmp_code == ICMP_HOST_ISOLATED ) {
        strncat(flag_string, "Host Isolated ", flag_size);
    }
    if ( icmp_code == ICMP_NET_ANO ) {
        strncat(flag_string, "Net Ano ", flag_size);
    }
    if ( icmp_code == ICMP_HOST_ANO ) {
        strncat(flag_string, "Host Ano ", flag_size);
    }
    if ( icmp_code == ICMP_NET_UNR_TOS ) {
        strncat(flag_string, "Net Unrecognized TOS ", flag_size);
    }
    if ( icmp_code == ICMP_HOST_UNR_TOS ) {
        strncat(flag_string, "Host Unrecognized TOS ", flag_size);
    }
    if ( icmp_code == ICMP_PKT_FILTERED ) {
        strncat(flag_string, "Packet Filtered ", flag_size);
    }
    if ( icmp_code == ICMP_PREC_VIOLATION ) {
        strncat(flag_string, "Precedence Violation ", flag_size);
    }
    if ( icmp_code == ICMP_PREC_CUTOFF ) {
        strncat(flag_string, "Precedence Cutoff ", flag_size);
    }
    if ( icmp_code == NR_ICMP_UNREACH ) {
        strncat(flag_string, "Unreachable ", flag_size);
    }

}

/******************************************************************************
* Get_ICMP_Flags:  Return a string of ICMP message type based on the header
*
******************************************************************************/

void get_icmp_flags(char *flag_string, int flag_size, u_char icmp_type, u_char icmp_code) {


    memset(flag_string,0,flag_size);
    //char code_string[20];  //removed as we don't collect ICMP codes in this version

    if ( icmp_type == ICMP_ECHOREPLY ) {
        strncat(flag_string, "REPLY", flag_size);
    }
    if ( icmp_type == ICMP_DEST_UNREACH ) {
        strncat(flag_string, "DST_UN", flag_size);

        //get_icmp_unreachable_codes(code_string, sizeof(code_string), icmp_code);
        //strncat(flag_string, code_string, flag_size);

    }
    if ( icmp_type == ICMP_SOURCE_QUENCH ) {
        strncat(flag_string, "SRC_Q", flag_size);

    }
    if ( icmp_type == ICMP_REDIRECT ) {
        strncat(flag_string, "REDIR", flag_size);
    }
    if ( icmp_type == ICMP_ECHO ) {
        strncat(flag_string, "ECHO", flag_size);

    }
    if ( icmp_type == ICMP_TIME_EXCEEDED ) {
        strncat(flag_string, "TIMEEX", flag_size);
    }
    if ( icmp_type == ICMP_PARAMETERPROB ) {
        strncat(flag_string, "P_PROB", flag_size);
    }
    if ( icmp_type == ICMP_TIMESTAMP ) {
        strncat(flag_string, "TIMEST", flag_size);
    }
    if ( icmp_type == ICMP_TIMESTAMPREPLY) {
        strncat(flag_string, "TIMERP", flag_size);
    }
    if ( icmp_type == ICMP_INFO_REQUEST ) {
        strncat(flag_string, "INFO_RQ", flag_size);
    }
    if ( icmp_type == ICMP_INFO_REPLY ) {
        strncat(flag_string, "INFO_RP", flag_size);
    }
    if ( icmp_type == ICMP_ADDRESS ) {
        strncat(flag_string, "ADDR", flag_size);
    }
    if ( icmp_type == ICMP_ADDRESSREPLY ) {
        strncat(flag_string, "ADDRRP", flag_size);
    }




}
/******************************************************************************
 * evaluate_packet:  figure out where to put it in the flow list
 *
 ******************************************************************************/
void evaluate_packet(Options *opts, struct flow_record *new_record){
    char new_src_addr[50];
    char new_dst_addr[50];
    char curr_src_addr[50];
    char curr_dst_addr[50];
    
    int add_record = 1;
    int i = 0;
    
    
    sprintf(new_src_addr, "%s:%d", new_record->source_address, new_record->source_port);
    sprintf(new_dst_addr, "%s:%d", new_record->destination_address, new_record->destination_port);
    
            
    while(( i<MAX_FLOWS) && (opts->flow_records[i].in_use == 1)){
        
        sprintf(curr_src_addr, "%s:%d", opts->flow_records[i].source_address, opts->flow_records[i].source_port);
        sprintf(curr_dst_addr, "%s:%d", opts->flow_records[i].destination_address, opts->flow_records[i].destination_port);
        //printf ("Comparing \n%s & %s \n to: \n%s & %s\n\n", curr_src_addr, curr_dst_addr, new_src_addr, new_dst_addr);
        
        
        // Append more packets to a one-way flow
        if ((opts->flow_records[i].in_use == 1) && (strcmp(curr_src_addr, new_src_addr) ==0) && (strcmp(curr_dst_addr, new_dst_addr)==0) && (opts->flow_records[i].start_time + opts->flow_timeout > new_record->start_time)) {
            //printf("Appending record\n");
            add_record=0;
            opts->flow_records[i].total_packets +=new_record->total_packets;
            opts->flow_records[i].total_bytes += new_record->total_bytes;
            opts->flow_records[i].end_time = new_record->end_time;
            strncpy(opts->flow_records[i].flags, new_record->flags, sizeof(opts->flow_records[i].flags));
            opts->flow_records[i].interactions +=1;
            
            // GAWD we need to check direction now!
            // if they're different, then it's a two-way flow
            if (strstr(opts->flow_records[i].direction, new_record->direction) == NULL) {
                strncpy(opts->flow_records[i].direction, "<->", sizeof(opts->flow_records[i].direction));
            }
            
            // We don't copy new direction when appending!
            //strncpy(opts->flow_records[i].direction, "->", sizeof(opts->flow_records[i].direction));
        }
        // Append packets to describe a two-way flow
        else if ((opts->flow_records[i].in_use == 1) && (strcmp(curr_src_addr, new_dst_addr) ==0) && (strcmp(curr_dst_addr, new_src_addr)==0) && (opts->flow_records[i].start_time + opts->flow_timeout > new_record->start_time)) {
            //printf("Appending record\n");
            add_record=0;
            opts->flow_records[i].total_packets +=new_record->total_packets;
            opts->flow_records[i].total_bytes += new_record->total_bytes;
            opts->flow_records[i].end_time = new_record->end_time;
            opts->flow_records[i].interactions +=1;
            strncpy(opts->flow_records[i].flags, new_record->flags, sizeof(opts->flow_records[i].flags));
            
            // We do change it in this case, since we now know it's bidirectional
            strncpy(opts->flow_records[i].direction, "<->", sizeof(opts->flow_records[i].direction));
        }
        i++;
    }
    // if we didn't append it, we need to add it to the record list
    if (add_record) {
        for (int i =0; i<MAX_FLOWS; i++) {
            if ((add_record) && (opts->flow_records[i].in_use == 0)) {
                //printf("Adding new record to index:  %i\n", i);
                add_record = 0;
                strncpy(opts->flow_records[i].protocol, new_record->protocol, sizeof(opts->flow_records[i].protocol));
                strncpy(opts->flow_records[i].destination_address, new_record->destination_address, sizeof(opts->flow_records[i].destination_address));
                strncpy(opts->flow_records[i].source_address, new_record->source_address, sizeof(opts->flow_records[i].source_address));
                
                opts->flow_records[i].destination_port = new_record->destination_port;
                opts->flow_records[i].source_port = new_record->source_port;
                strncpy(opts->flow_records[i].direction, new_record->direction, sizeof(opts->flow_records[i].direction));
                
                opts->flow_records[i].start_time = new_record->start_time;
                opts->flow_records[i].end_time = new_record->end_time;
                
                strncpy(opts->flow_records[i].flags, new_record->flags, sizeof(opts->flow_records[i].flags));
                opts->flow_records[i].in_use = new_record->in_use;

                opts->flow_records[i].total_bytes = new_record->total_bytes;
                opts->flow_records[i].total_packets = new_record->total_packets;
                strncpy(opts->flow_records[i].direction, new_record->direction, sizeof(opts->flow_records[i].direction));
                opts->flow_records[i].interactions =1;
                
            }
        }
    }
    if(add_record) {
        printf("Insufficient buffer space!!!\n");
    }
}


/******************************************************************************
 * print_flow_record:  print flows that should be printed...
 *
 ******************************************************************************/
void print_flow_record(Options *opts, int index) {
    
    static int records_printed = 0;
    static int header_printed = 0;
    
    double flow_age = 0;
    
    char src_port[5] ;
    char dst_port[5] ;
    struct flow_record *record;
    
    if (header_printed == 0) {
        printf("%-18s%-7s%-14s%-7s%-6s%-14s%-10s%-8s%-18s%-7s%-5s\n", "StartTime", "Proto", "SrcAddr", "Sport", "Dir", "DstAddr", "Dport", "TotPkts", "TotBytes", "State","Dur");
        header_printed = 1;
    }
    
    
    if ((opts->num_flow_records_set) && (records_printed >= opts->num_flow_records) ) {
        return;
    } else {
        record = &opts->flow_records[index];
        
        flow_age = record->end_time - record->start_time;
        
        sprintf(src_port, "%d", record->source_port );
        sprintf(dst_port, "%d", record->destination_port);
        if (strcmp(record->protocol, "ICMP") == 0) {
            sprintf(src_port, " ");    //little formating ugliness to replace "port 0" with a blank space for ICMP
            sprintf(dst_port, " ");    //ditto
        }
        
        printf("%.06f%5s%16s%5s%6s%16s%5s%10d%10d%18s %5f  %d\n", record->start_time, record->protocol, record->source_address, src_port, record->direction, record->destination_address, dst_port, record->total_packets,
               record->total_bytes, record->flags, flow_age, record->interactions);
        records_printed++;

        
    }
    
    
    
}

/******************************************************************************
* process_packet:  callback function called by pcap_loop
*
******************************************************************************/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {


    //const struct ethernet_packet *ethernet_header;
    const struct ip_packet_header *ip_header;
    const struct tcp_packet_header *tcp_header;
    const struct udp_packet_header *udp_header;
    const struct icmp_packet_header *icmp_header;
    int size_ip;
    int size_tcp;
    char tcp_flags_str[50];
    char icmp_flags_str[150];
    double packet_time = 0;
    int print_record = 1;
    int packet_length = 0;
    struct flow_record new_record;
    int purge_buffer = 0;
    int elapsed_time =0;
    



    Options *opts = (Options *)args;
    packet_time = header->ts.tv_sec +(header->ts.tv_usec/1000000.0);




    
    
    // Logic to handle the use of the -t when capturing a "live" interface
    if ((opts->interface) && (opts->time_set)) {
        if (packet_time > opts->time_start + opts->time ) {
            purge_buffer = 1;
            print_flows(opts, purge_buffer);
            elapsed_time = packet_time - opts->time_start;
            printf ("\n\nTimes Up!   Exiting after %d seconds\n\n", elapsed_time);
            exit(0);
        }
    }
    
    
    // Logic to capture use of the -t (time) and -o (offset) switches when working offline
    if ((opts->file) && (opts->time_set) && (opts->time_offset_set) ) {
        if (!((packet_time >= opts->time) && (packet_time <= (opts->time + opts->time_offset) ))) {
            print_record = 0;
        }
    } else if ((opts->file) && (opts->time_set) && !(opts->time_offset_set)) {
        if (!(packet_time >= opts->time)) {
            print_record = 0;
        }
    }
    
/*    if (print_record) {
        printf("%d.%06d ", (int)header->ts.tv_sec,(int)header->ts.tv_usec);
    }*/
    

    //Parse out the ethernet header
    //ethernet_header = (struct ethernet_packet*)(packet);


    //Parse out the IP header
    ip_header = (struct ip_packet_header*)(packet + ETHERNET_PACKET_LENGTH);


    size_ip=IP_HL(ip_header) *4;
    if (size_ip < 20) {
        if(print_record) {
            printf("   * Invalid IP header length:  %u bytes \n", size_ip);
        }

    }


    switch (ip_header->ip_protocol) {
        case IPPROTO_TCP:
            //parse out the TCP Header
            tcp_header = (struct tcp_packet_header*)(packet +ETHERNET_PACKET_LENGTH + size_ip);

            //Now grab the data we need to print
            size_tcp = TCP_DATA_OFF(tcp_header)*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            get_tcp_flags(tcp_flags_str, sizeof(tcp_flags_str), tcp_header->tcp_flags);

            packet_length = header->len;
            if (print_record) {
                
                if ((strstr(tcp_flags_str, "ACK SYN") !=NULL) || (strstr(tcp_flags_str, "RST") !=NULL) || (strstr(tcp_flags_str, "FIN") !=NULL)){
                    //If it's a SYNACK, A FIN, or a RSTwe have to flip the order to show right transmitting to left
                    strncpy( new_record.source_address, inet_ntoa(ip_header->ip_destination), sizeof(new_record.source_address));
                    strncpy( new_record.destination_address, inet_ntoa(ip_header->ip_source), sizeof(new_record.destination_address));
                    new_record.source_port = ntohs(tcp_header->tcp_destination_port);
                    new_record.destination_port = ntohs(tcp_header->tcp_source_port);

                    strncpy(new_record.direction, "<-", sizeof(new_record.direction));
                    
                } else {
                    
                    strncpy( new_record.source_address, inet_ntoa(ip_header->ip_source), sizeof(new_record.source_address));
                    strncpy( new_record.destination_address, inet_ntoa(ip_header->ip_destination), sizeof(new_record.destination_address));
                    new_record.source_port = ntohs(tcp_header->tcp_source_port);
                    new_record.destination_port = ntohs(tcp_header->tcp_destination_port);

                    strncpy(new_record.direction, "->", sizeof(new_record.direction));
                    
                }
                
                
                
                
                strncpy(new_record.protocol, "TCP", sizeof(new_record.protocol));
                
                
                
                
                new_record.start_time = packet_time;
                new_record.end_time = packet_time;
                
                
                new_record.total_packets = 1;
                new_record.total_bytes= header->len;
                
                
                strncpy(new_record.flags, tcp_flags_str, sizeof(new_record.flags));
                new_record.in_use = 1;
                
                
                
                evaluate_packet(opts, &new_record);
               
                
                
            }
            
 /*           if (print_record) {
                printf("%4s %16s:%-5d %16s:%-5d len %3u flags:%s seq %u ack %u\n", "TCP", inet_ntoa(ip_header->ip_source), ntohs(tcp_header->tcp_source_port),
                    inet_ntoa(ip_header->ip_destination), ntohs(tcp_header->tcp_destination_port), packet_length , tcp_flags_str,
                    tcp_header->tcp_sequence_number, tcp_header->tcp_acknowledgement_number);
            }*/

            break;
        case IPPROTO_UDP:
            //parse out the UDP header
            udp_header = (struct udp_packet_header*)(packet+ETHERNET_PACKET_LENGTH+size_ip);
            packet_length = header->len;
            /*if (print_record) {
                printf("%4s %16s:%-5d %16s:%-5d len %3u\n", "UDP", inet_ntoa(ip_header->ip_source), ntohs(udp_header->udp_source_port),
                    inet_ntoa(ip_header->ip_destination), ntohs(udp_header->udp_destination_port), packet_length);
            }*/
            if (print_record) {
                strncpy(new_record.protocol, "UDP", sizeof(new_record.protocol));
                strncpy( new_record.source_address, inet_ntoa(ip_header->ip_source), sizeof(new_record.source_address));
                strncpy( new_record.destination_address, inet_ntoa(ip_header->ip_destination), sizeof(new_record.destination_address));
                
                new_record.source_port = ntohs(udp_header->udp_source_port);
                new_record.destination_port = ntohs(udp_header->udp_destination_port);
                
                new_record.start_time = packet_time;
                new_record.end_time = packet_time;
                
                new_record.total_packets = 1;
                new_record.total_bytes= header->len;
                
                strncpy(new_record.flags, "  ", sizeof(new_record.flags));
                new_record.in_use = 1;
                strncpy(new_record.direction, "->", sizeof(new_record.direction));
                
                evaluate_packet(opts, &new_record);
                
            }


            break;
        case IPPROTO_ICMP:

            //parse out the ICMP header
            icmp_header = (struct icmp_packet_header*)(packet+ETHERNET_PACKET_LENGTH+size_ip);
            get_icmp_flags(icmp_flags_str, sizeof(icmp_flags_str), icmp_header->icmp_type, icmp_header->icmp_code);
            packet_length = header->len;
            /*if (print_record) {
                printf("%4s %16s %22s       len  %3u %s\n", "ICMP", inet_ntoa(ip_header->ip_source), inet_ntoa(ip_header->ip_destination), packet_length, icmp_flags_str);
            }*/
            if (print_record) {
                strncpy(new_record.protocol, "ICMP", sizeof(new_record.protocol));
                if ((strstr(icmp_flags_str, "REPLY") !=NULL) || (strstr(icmp_flags_str, "DST_UN") !=NULL) || (strstr(icmp_flags_str, "SRC_Q") !=NULL)
                    ||(strstr(icmp_flags_str, "TIMERP") !=NULL) || (strstr(icmp_flags_str, "INF_RP") !=NULL) || (strstr(icmp_flags_str, "ADDRRP") !=NULL)){
                    strncpy( new_record.source_address, inet_ntoa(ip_header->ip_destination), sizeof(new_record.source_address));
                    strncpy( new_record.destination_address, inet_ntoa(ip_header->ip_source), sizeof(new_record.destination_address));
                    strncpy(new_record.direction, "<-", sizeof(new_record.direction));
                } else {
                    strncpy( new_record.source_address, inet_ntoa(ip_header->ip_source), sizeof(new_record.source_address));
                    strncpy( new_record.destination_address, inet_ntoa(ip_header->ip_destination), sizeof(new_record.destination_address));
                    strncpy(new_record.direction, "->", sizeof(new_record.direction));
                }
                
                
                
                strncpy( new_record.source_address, inet_ntoa(ip_header->ip_source), sizeof(new_record.source_address));
                strncpy( new_record.destination_address, inet_ntoa(ip_header->ip_destination), sizeof(new_record.destination_address));
                
                new_record.source_port = 0;
                new_record.destination_port = 0;
                
                new_record.start_time = packet_time;
                new_record.end_time = packet_time;
                
                new_record.total_packets = 1;
                new_record.total_bytes= header->len;
                
                strncpy(new_record.flags, icmp_flags_str, sizeof(new_record.flags));
                new_record.in_use = 1;
                
                
                evaluate_packet(opts, &new_record);
                
            }

        default:

            break;
    }
 //   print_flows(opts, purge_buffer);
    
    
    


    
}


/******************************************************************************
* Open_File:  Open an offline file & process the packets found
*
******************************************************************************/
int Open_File(Options *Opt) {


    char *dev = NULL;
    //bpf_u_int32 netmask;
    //bpf_u_int32 ip_address;
    char  errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_expression[] = " ip";
    struct bpf_program compiled_filter;
    

    dev = Opt->file_name;

    //Open the file
    handle = pcap_open_offline(dev,  errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    //Compile the filter
    if (pcap_compile(handle, &compiled_filter, filter_expression, 0, PCAP_NETMASK_UNKNOWN) ==-1) {
        fprintf(stderr, "Couldn't compile filter.  Error:  %s", pcap_geterr(handle));
        return(2);

    }
    //Apply the filter
    if (pcap_setfilter(handle, &compiled_filter) == -1 ) {
            fprintf(stderr, "Couldn't apply filter to %s.  Error:  %s\n", dev, pcap_geterr(handle));
        return(2);
    }

    Opt->time_start = time(NULL);
    printf("Reading file at %ld\n\n", Opt->time_start);
    //Now the magic happens...
    pcap_loop(handle, -1, (pcap_handler)process_packet, (u_char*)Opt);
    
    // Purge the fsniffer buffer of collected streams
    //print_flows(Opt, 1);
    print_scans(Opt, 1);
    //print_flows(Opt, 1);
    
    //Close the file (TODO:  add error handling that includes closing the file)
    pcap_close(handle);

    return 0;
}
/******************************************************************************
* Open_Interface:  Open a live interface & process packets
*
******************************************************************************/
int Open_Interface(Options *Opt) {

    /* default snap length (maximum bytes per packet to capture) */
    #define SNAP_LEN 1518

    char *dev = NULL;
    bpf_u_int32 netmask;
    bpf_u_int32 ip_address;
    char  errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_expression[] = " ip";
    struct bpf_program compiled_filter;


    dev = Opt->interface_name;


    //Open the file
    //handle = pcap_open_offline(dev,  errbuf);

     if (pcap_lookupnet(dev, &ip_address, &netmask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
                ip_address = 0;
                netmask = 0;
        }

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    //

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    //Compile the filter
    if (pcap_compile(handle, &compiled_filter, filter_expression, 0, PCAP_NETMASK_UNKNOWN) ==-1) {
        fprintf(stderr, "Couldn't compile filter.  Error:  %s", pcap_geterr(handle));
        return(2);

    }
    //Apply the filter
    if (pcap_setfilter(handle, &compiled_filter) == -1 ) {
            fprintf(stderr, "Couldn't apply filter to %s.  Error:  %s\n", dev, pcap_geterr(handle));
        return(2);
    }
    
    Opt->time_start = time(NULL);
    printf("Starting capture at %ld\n\n", Opt->time_start);
    //Now the magic happens...
    pcap_loop(handle, -1, (pcap_handler)process_packet, (u_char*)Opt);

    //Close the file (TODO:  add error handling that includes closing the file)
    pcap_close(handle);


    return 0;
}



/******************************************************************************
 * print_flows:  print flows that should be printed...
 *
 ******************************************************************************/
void print_flows(Options *opts, int purge_buffer) {
    
    
    double flow_age = 0;
    
    
    for (int i =0; i< MAX_FLOWS; i++) {
        
        // Records that are older than the -S parameter
        if (opts->flow_records[i].in_use) {
            flow_age = opts->flow_records[i].end_time - opts->flow_records[i].start_time;
            if (flow_age >opts->flow_timeout) {
                print_flow_record(opts, i);
                opts->flow_records[i].in_use = 0;
                
            }
            
        }
        //Records that have TCP markers indicating a session end
        if (opts->flow_records[i].in_use) {
            if ((strstr(opts->flow_records[i].flags,"ACK FIN") != NULL) || (strstr(opts->flow_records[i].flags,"RST") != NULL) ){
                print_flow_record(opts, i);
                opts->flow_records[i].in_use = 0;
                
            }
            
        }
        
        
        
        // Records that have ICMP End Markers
        if (opts->flow_records[i].in_use) {
            if ((strstr(opts->flow_records[i].flags,"REPLY") != NULL) || (strstr(opts->flow_records[i].flags,"SRC_Q") != NULL) || (strstr(opts->flow_records[i].flags,"SRC_Q") != NULL)
                || (strstr(opts->flow_records[i].flags,"REDIR") != NULL) || (strstr(opts->flow_records[i].flags,"INF_RP") != NULL) || (strstr(opts->flow_records[i].flags,"ADDRRP") != NULL)){
                print_flow_record(opts, i);
                opts->flow_records[i].in_use = 0;
                
            }
            
        }
    }
    if (purge_buffer) {
        for (int i =0; i< MAX_FLOWS; i++) {
            if (opts->flow_records[i].in_use) {
                print_flow_record(opts, i);
                opts->flow_records[i].in_use = 0;
                
            }
        }
        
    }
    
    
    
}

void add_scanner_record(struct scanner scanlist[], struct options *opt, int index) {
    int add_scanner = 1;
    int i = 0;
    char port_string[5] = "";
    
    
    while ((i < MAX_SCANNERS) && (add_scanner ==1)) {
        if ((strcmp(scanlist[i].source_address, opt->flow_records[index].source_address) ==0) && (strcmp(scanlist[i].destination_address, opt->flow_records[index].destination_address) ==0) && (strcmp(scanlist[i].protocol, opt->flow_records[index].protocol) ==0)) {
            add_scanner = 0;
            scanlist[i].port_count +=1;
            //sprintf(port_string, "%d", opt->flow_records[index].destination_port);
            //strncat(scanlist[i].port_list, port_string, sizeof(scanlist[i].port_list));
        }
        if (strcmp(scanlist[i].source_address, "") ==0)  {
            add_scanner = 0;
            strncpy(scanlist[i].source_address, opt->flow_records[index].source_address, sizeof(scanlist[i].source_address));
            strncpy(scanlist[i].destination_address, opt->flow_records[index].destination_address, sizeof(scanlist[i].destination_address));
            scanlist[i].port_count +=1;
            strncpy(scanlist[i].protocol,opt->flow_records[index].protocol, sizeof(scanlist[i].protocol));
            //sprintf(port_string, "%d", opt->flow_records[index].destination_port);
            //strncat(scanlist[i].port_list, port_string, sizeof(scanlist[i].port_list));
        }
        i++;
        
    }
}






void print_scans(Options *Opt, int purge_buffer) {
    
    struct scanner hostlist[MAX_SCANNERS];
    struct scanner scannerlist[MAX_SCANNERS];
    int num_scanners=0;
    double last_time, this_time;
    char maybe_scanner[16];
    
    
    for (int i=0; i<MAX_SCANNERS; i++) {
        
        strncpy(hostlist[i].source_address, "", sizeof(hostlist[i].source_address));
        memset(hostlist[i].destination_address, 0, sizeof(hostlist[i].destination_address));
        memset(hostlist[i].protocol, 0, sizeof(hostlist[i].protocol));
        memset(hostlist[i].port_list, 0, sizeof(hostlist[i].port_list));
        hostlist[i].port_count = 0;
        hostlist[i].host_count = 0;
        
        strncpy(scannerlist[i].source_address, "", sizeof(scannerlist[i].source_address));
        memset(scannerlist[i].destination_address, 0, sizeof(scannerlist[i].destination_address));
        memset(scannerlist[i].protocol, 0, sizeof(scannerlist[i].protocol));
        memset(scannerlist[i].port_list, 0, sizeof(scannerlist[i].port_list));
        scannerlist[i].port_count = 0;
        scannerlist[i].host_count = 0;
    }		
    last_time = 0;
    this_time =0;
    strncpy(maybe_scanner, "", sizeof(maybe_scanner));
    
    
    for (int i = 0; i< MAX_FLOWS; i++) {
        if (Opt->flow_records[i].in_use == 1) {
            add_scanner_record(hostlist, Opt, i);
    
     }
     
     
     }

     for (int i = 0; i< MAX_SCANNERS	; i++) {
         if (strcmp(hostlist[i].source_address,"")!=0) {
           //  printf("%s %s %s %d %s\n", hostlist[i].source_address, hostlist[i].destination_address, hostlist[i].protocol, hostlist[i].port_count, hostlist[i].port_list );
         }
     }
    
    int added=0;
    for (int i=0; i<MAX_SCANNERS; i++) {
        added=0;
        for (int j=0; j<MAX_SCANNERS; j++) {
            if((added==0) && (strcmp(hostlist[i].source_address, "") !=0) && ( strcmp(hostlist[i].source_address, scannerlist[j].source_address ) ==0)) {
                scannerlist[j].host_count +=1;
                scannerlist[j].port_count +=hostlist[i].port_count;
                added=1;
            }
            else if ((added==0) && (strcmp(hostlist[i].source_address, "") !=0) && 		(strcmp(scannerlist[j].source_address,"")==0)) {
                strncpy(scannerlist[j].source_address, hostlist[i].source_address, sizeof(scannerlist[j].source_address));
                scannerlist[j].host_count +=1;
                scannerlist[j].port_count +=hostlist[i].port_count;
                added=1;
            }
        }
    }
    
    printf("Summary:\n");
    printf("Scanner	\t\t#HostsScanned	\t#PortsScanned\n");
    for (int i = 0; i< MAX_SCANNERS	; i++) {
        if (strcmp(scannerlist[i].source_address,"")!=0) {
            printf("%-18s\t\t%d\t\t\t%d\n", scannerlist[i].source_address,   scannerlist[i].host_count, scannerlist[i].port_count );
        }
    }
    
    
}
