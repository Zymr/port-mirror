#ifndef GRE_ENCAPSULATION_H_   
#define GRE_ENCAPSULATION_H_

#include "pcap.h"

#define CRC 0xf296						/* Validation disabled .TODO */
#define FLAGS 0x4000					/* Freagment offset 0.No fragment*/
#define IDENTIFICATION  0xf322
#define PROTO 0x2f						/* Protocol GRE */
#define TTL 0xff
#define VER 0x45
#define TOS 0x00
#define GRE_PROTO 0x0800				/* Protocol IP*/
#define GRE_VER 0x0000
#define IP_HEADER 20
#define GRE_HEADER 4
#define FRAME_LENGTH 14

/* Structure for 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* Struct for IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
}ip_header;

/* Struct for GRE header */
char gre_header_data[4];

/** Fuction to update IP header 
 *
 * This function updates the outer IPv4 header 
 * @param[in]		struct IPv4 header
 * @param[in]		struct of original IPv4 header
 * @param[in]		source ip address
 * @param[in]		destination ip address
 */
void update_ip_header(struct ip_header *ip, struct ip_header newip, unsigned long source, unsigned long destination);

#endif // GRE_ENCAPSULATION_H_