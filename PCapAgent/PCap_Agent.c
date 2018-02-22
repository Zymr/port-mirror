#include "GRE_Encapsulation.h"

int main(int argc, char** argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *device;
	int interface_num;
	int i = 0;
	int res = 1;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *adhandle;
	struct pcap_pkthdr *header;
	u_char *pkt_data;
	const u_char mirror_pkt_data[1500];

	/* Retrieve the device list on the local machine*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (device = alldevs; device; device = device ->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &interface_num);

	unsigned long source = inet_addr(scrIP);
	unsigned long dest = inet_addr(destIP);
	
	if (interface_num < 1 || interface_num > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (device = alldevs, i = 0; i <interface_num - 1; device = device->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(device->name,     // name of the device
		65536,									// portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS,				// promiscuous mode
		1000,									// read timeout
		NULL,									// authentication on the remote machine
		errbuf									// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", device->description);
	pcap_freealldevs(alldevs);

	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		/*First Extract Original Header */
		ip_header originalHeader;
		memcpy(&originalHeader, &pkt_data[14], IP_HEADER);

		ip_header ip;
		/* Update IP header */
		update_ip_header(&ip, originalHeader, source, dest);

		/* Check for already encapsulated packet*/
		if (originalHeader.proto != (PROTO))
		{
			unsigned short originalLength = ((originalHeader.tlen & 0xFF00) >> 8) | ((originalHeader.tlen & 0x00FF) << 8);
			unsigned short newGreLength = originalLength + IP_HEADER + GRE_HEADER;
			ip.tlen = ((newGreLength & 0xFF00) >> 8) | ((newGreLength & 0x00FF) << 8);
			ip.identification = ((ip.identification & 0xFF00) >> 8) | ((ip.identification & 0x00FF) << 8);
			ip.crc = ((ip.crc & 0xFF00) >> 8) | ((ip.crc & 0x00FF) << 8);
			ip.flags_fo = ((ip.flags_fo & 0xFF00) >> 8) | ((ip.flags_fo & 0x00FF) << 8);

			/* Encapsulate IP and GRE header */
			memcpy(&mirror_pkt_data[0], &pkt_data[0], FRAME_LENGTH);
			memcpy(&mirror_pkt_data[FRAME_LENGTH], &ip, IP_HEADER);
			memcpy(&mirror_pkt_data[FRAME_LENGTH + IP_HEADER], &gre_header_data, GRE_HEADER);
			memcpy(&mirror_pkt_data[FRAME_LENGTH + IP_HEADER + GRE_HEADER], &pkt_data[FRAME_LENGTH], (header->caplen - FRAME_LENGTH));

			/* Send the Encapsulated packet */
			pcap_sendpacket(adhandle, &mirror_pkt_data[0], header->caplen + IP_HEADER + GRE_HEADER);
			printf("Captured and Encapsulating Packet GRE \n");

		}
	}
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}






