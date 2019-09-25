#include "CLIManager.h"
#include "GRE_Encapsulation.h"


int main(int argc, char* argv[])
{
	tParsedData parsed;
	parsed = parseCLI(argc, argv);

	if (!parsed.isValidCmd)
	{
		return -1;
	}
	if (!parsed.isCaptureCmd)
	{
		return -1;
	}

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
	const u_char ip_gre_header[24];

	struct bpf_program fcode;
	u_int netmask;
	char* interfaceName = NULL;
	char* filter = NULL;

	/* Retrieve the device list on the local machine*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	if (parsed.displayInterfaces)
	{
		/* Print the list */
		for (device = alldevs; device; device = device->next)
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
		return 0;
	}

	/* Print the list */
	for (device = alldevs; device; device = device->next)
	{
		++i;
	}
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	interface_num = parsed.interfaceNumber;

	if (interface_num < 1 || interface_num > i)
	{
		printf("\n%d:: Interface number out of range.\n", interface_num);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter */
	for (device = alldevs, i = 0; i <interface_num - 1; device = device->next, i++);
	interfaceName = device->name;

	/* Open the device */
	if ((adhandle = pcap_open(interfaceName,    // name of the device
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

	filter = parsed.filter;

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", device->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	unsigned long source = inet_addr(parsed.localIP);
	unsigned long dest = inet_addr(parsed.remoteIP);

	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;
		//First Extract Original Header
		ip_header originalHeader;
		memcpy(&originalHeader, &pkt_data[14], IP_HEADER);

		ip_header ip;
		update_ip_header(&ip, originalHeader, source, dest);

		if (originalHeader.proto != (PROTO))
		{

			unsigned short originalLength = ((originalHeader.tlen & 0xFF00) >> 8) | ((originalHeader.tlen & 0x00FF) << 8);

			//ip_header newGreHeader;
			unsigned short newGreLength = originalLength + IP_HEADER + GRE_HEADER;
			ip.tlen = ((newGreLength & 0xFF00) >> 8) | ((newGreLength & 0x00FF) << 8);
			//	printf("newGreLength %d\n", newGreLength);
			ip.identification = ((ip.identification & 0xFF00) >> 8) | ((ip.identification & 0x00FF) << 8);
			ip.crc = ((ip.crc & 0xFF00) >> 8) | ((ip.crc & 0x00FF) << 8);
			ip.flags_fo = ((ip.flags_fo & 0xFF00) >> 8) | ((ip.flags_fo & 0x00FF) << 8);
			memcpy(&mirror_pkt_data[0], &pkt_data[0], FRAME_LENGTH);
			memcpy(&mirror_pkt_data[FRAME_LENGTH], &ip, IP_HEADER);
			memcpy(&mirror_pkt_data[FRAME_LENGTH + IP_HEADER], &gre_header_data, GRE_HEADER);
			memcpy(&mirror_pkt_data[FRAME_LENGTH + IP_HEADER + GRE_HEADER], &pkt_data[FRAME_LENGTH], (header->caplen - FRAME_LENGTH));
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




