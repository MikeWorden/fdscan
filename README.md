cs557 Homework 2				Michael Worden

fsniffer - a Packet Sniffer Using libpcap that looks at streams

This tool implements the project described in http://www.cs.colostate.edu/~557/hw2.html

This is a command-line tool that captures packets from a file or from a live interface.  
The syntax is:
	%fsniffer [-r filename] [-i interface] [-t time] [-o time_offset] [-N num] [-S secs]

The tool outputs  TCP streams, UDP streams , and ICMP streams
When the tool reads trace files, the records whose timestamp drops in the range [time, time + offset] are printed out. If "-t" is not used, the tool prints out packets from the beginning of the trace file. If "-o" is not used, the tool prints out packets whose timestamp start from the specified time to the end of the captured trace file. 
When capturing packets live from an interface, the offset option is ignored, and the time option specifies the running time of the sniffer. If the time option is not specified, and the sniffer is in live capture mode, the sniffer will keep running until it is killed. The time option, offset option should accept numbers in seconds, for instance, "-t 1484868635" for trace file reading means the start timestamp is Unix epoch time 1484868635, and "-o 0.01" means the offset is 0.01 sec. 
-N specifies the first N flow records.   The default is to print all records
-S specifies the timeout interval for a flow


Note 1:     To build, cd to 'h2.worden.mike' & run 'make clean && make'  
Note 2:     I considered the following packet as "flows" that should be sent as records:
All:    
            Any stream that exceeds the timeout specified in [-S secs] option (or 60s default)

TCP:
            Any TCP stream from the same source/destination IPs, which ends in:
            FIN ACK 
            RST
UDP:
            None -- the nature of UDP does not lend itself to definition of a flow.   
            (As stated in RFC 768:  "applications requiring ordered reliable delivery of
            streams of data should use the Transmission Control Protocol (TCP)"
            considered select UDP applicaitons like DNS request/responses, however,
            defining the close was problematic (for example, doing a single lookup
            like 'nslookup www.google.com' produced a recognizeable pattern, but 
            nslookup type=mx foo.com  108.61.210.155 could provide subsequent packets
            (or not) depending on the number of MX records provided by the DNS server

ICMP:
            Any  of the following (from same source/destination ips):
                ICMP_ECHO    followed by ICMP_ECHOREPLY
                ICMP_ECHO    followed by ICMP_DEST_UNREACH
                ICMP_INFO_REQUEST  followed by ICMP_INFO_REPLY
                ICMP_ADDRESS        followed by ICMP_ADDRESSREPLY

Note 3:   To support cleaner output, the following ICMP type abbreviations will be used.

ICMP Message       TYPE fsniffer Abbreviation
ICMP_ECHOREPLY      0	REPLY
ICMP_DEST_UNREACH	3	DST_UN
ICMP_SOURCE_QUENCH	4	SRC_Q
ICMP_REDIRECT       5	REDIR
ICMP_ECHO           8	ECHO
ICMP_TIME_EXCEEDED	11	TIMEEX
ICMP_PARAMETERPROB	12	P_PROB
ICMP_TIMESTAMP      13	TIMEST
ICMP_TIMESTAMPREPLY	14	TIMERP
ICMP_INFO_REQUEST	15	INF_RQ
ICMP_INFO_REPLY     16	INF_RP
ICMP_ADDRESS        17	ADDR
ICMP_ADDRESSREPLY	18	ADDRRP
This program leveraged the example of Tim Carsten's sniffex.c found at 
http://tcpdump.org/sniffex.c. 
This program relies heavily on casting of structures to data blobs.  This 
approach is both powerful, but incredibly risky.   The standard approach 
used throughout this program is to grab a packet, then in the pcap_loop 
callback map portions of memory to the ethernet, IP, TCP, UDP or ICMP packet 
structures.   Then print it out what you find.  But the danger is when the 
packets don't match the data structures you've defined.  When run as a user, 
the program may crash when this happens.  When run as root, the corresponding 
manipulation of memory as a privileged user means the system could be damaged 
further.
In addition to Tim Carsten's excellent example, I relied on the following RFCs:

    RFC 791 Internet Protocol
    RFC 768 User Datagram Protocol
    RFC 793 Transmission Control Protocol
    RFC 792 Internet Control Message Protocol
    
I also leaned heavily on the definitions found in the header files:
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    
Acknowledgements
    
	
# fdscan
