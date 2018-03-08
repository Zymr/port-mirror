#include "GRE_Encapsulation.h"

/* Function to update ip header*/
void update_ip_header(struct ip_header *ip, unsigned long source, unsigned long destination)
{
	ip->crc = CRC;
	ip->flags_fo = FLAGS;
	ip->tos = TOS;
	ip->identification = IDENTIFICATION;
	ip->proto = PROTO;
	ip->ttl = TTL;
	ip->ver_ihl = VER;

	memcpy(&ip->saddr, &source, 4);
	memcpy(&ip->daddr, &destination, 4);
}

/* Function to update ethernet header*/
void update_ethernet_header(struct ethernet_header *outer_ether_hdr, u_char local_s_mac[6], u_char remote_s_mac[6])
{
	memcpy(outer_ether_hdr->source, &local_s_mac[0], 6);	//Local ip MAC
	memcpy(outer_ether_hdr->dest, &remote_s_mac[0], 6);		//Remote ip MAC
	outer_ether_hdr->type = htons(0x0800);					//IP Protocol
}

/* Gre header data*/
char gre_header_data[] = { 0x00, 0x00, 0x08, 0x00 };

/* Function to join two bytes to u_short */
u_short BytesTo16(u_char X, u_char Y)
{
	u_short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}

/* Function to calculate IPv4 checksum*/
u_short CalculateIPChecksum(u_char IpPacket[20])
{
	u_short CheckSum = 0;
	for (int i = 0; i<20; i += 2)
	{
		u_short Tmp = BytesTo16(IpPacket[i], IpPacket[i + 1]);
		u_short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference){ CheckSum += 1; }
	}
	CheckSum = ~CheckSum;
	return CheckSum;
}


