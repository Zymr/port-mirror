#include "GRE_Encapsulation.h"

void update_ip_header(struct ip_header *ip, struct ip_header newip, unsigned long source, unsigned long destination)
{

	ip->crc = CRC;
	ip->flags_fo = FLAGS;
	ip->tos = 0;
	ip->identification = IDENTIFICATION;
	ip->proto = PROTO;
	ip->ttl = TTL;
	ip->ver_ihl = VER;

	memcpy(&ip->saddr, &source, 4);
	memcpy(&ip->daddr, &destination, 4);

}

char gre_header_data[] = { 0x00, 0x00, 0x08, 0x00 };
const char scrIP[] = "192.168.10.48";
const char destIP[] = "192.168.10.74";
