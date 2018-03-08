#ifndef GRE_ENCAPSULATION_H_   
#define GRE_ENCAPSULATION_H_

#include<stdbool.h>
#include "pcap.h"
#include <winsock2.h> 
#include <windows.h> 

#define CRC 0x0000						// Initaly 0 for CRC calculation 
#define FLAGS 0x4000					// Fragment offset 0 ie no fragment
#define IDENTIFICATION  0x00ff			
#define PROTO 0x2f						// Protocol GRE 
#define TTL 0xff
#define VER 0x45
#define TOS 0x00

#define IP_HEADER 20
#define GRE_HEADER 4
#define FRAME_LENGTH 14

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;					// Version (4 bits) + Internet header length (4 bits)
	u_char  tos;						// Type of service 
	u_short tlen;						// Total length 
	u_short identification;				// Identification
	u_short flags_fo;					// Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;						// Time to live
	u_char  proto;						// Protocol
	u_short crc;						// Header checksum
	ip_address  saddr;					// Source address
	ip_address  daddr;					// Destination address
}ip_header;

/* GRE header */
char gre_header_data[4];

/* Ethernet Header*/
typedef struct ethernet_header
{
	u_char dest[6];						// Destination IP MAC
	u_char source[6];					// Source IP MAC
	u_short type;						// IP Protocol Frame
} ethernet_hdr;

/* Function to join two bytes to u_short */
u_short BytesTo16(u_char X, u_char Y);

/* Fuction to calculate IP checksum */
u_short CalculateIPChecksum(u_char IpPacket[20]);

/* Fuction to update IP header */
void update_ip_header(struct ip_header *ip, unsigned long source, unsigned long destination);

/* Fuction to update IP header */
void update_ethernet_header(struct ethernet_header *outer_ether_hdr, u_char local_s_mac[6], u_char remote_s_mac[6]);

#endif // GRE_ENCAPSULATION_H_