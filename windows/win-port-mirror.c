#define HAVE_REMOTE
#define WPCAP

#include "CLIManager.h"
#include "GRE_Encapsulation.h"
#include "adapter.h"

// Link with Iphlpapi.lib
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib,"ws2_32.lib")			//For winsock
#pragma comment(lib,"wpcap.lib")			//For winpcap

#define WORKING_BUFFER_SIZE 1500
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

void showDevicesList();

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
	if (parsed.displayInterfaces)
	{
		showDevicesList();
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
	u_char mirror_pkt_data[2000];
	u_char cal_crc[20];

	struct bpf_program fcode;
	u_int netmask;
	char* interfaceName = NULL;
	char* filter = NULL;
	char guid[40];

	IN_ADDR srcip,desip;
	
	loadiphlpapi();
	
	/* Retrieve the device list on the local machine*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	char prefixToGUID[100] = "rpcap://\\Device\\NPF_";
	strcpy(guid, parsed.guid);
	strcat(prefixToGUID, guid);
	bool foundMatchingInterface = false;

	/* Extracting device with matching guid passed through cli */
	for (device = alldevs; device; device = device->next)
	{
		++i;
		if (strcmp(device->name, prefixToGUID) == 0) {
			interface_num = i;
			foundMatchingInterface = true;
			break;
		}
	}

	if (i == 0 || !foundMatchingInterface)
	{
		printf("\nNo interfaces found!\n");

		return -1;
	}

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
		1500,									// portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS,				// promiscuous mode
		10000,									// read timeout
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

	if (device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	/* compile the filter */
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* set the filter */
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	u_char local_s_mac[6], remote_s_mac[6];

	/* Get mac addresses of source and destination ips */
	struct sockaddr_in inaddr;
	inet_pton(AF_INET, parsedData.localIP, &inaddr.sin_addr.S_un.S_addr);
	srcip = (inaddr.sin_addr);

	GetMacAddress(local_s_mac, srcip);
	printf("\nMAC address of local machine : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", local_s_mac[0], local_s_mac[1], local_s_mac[2], local_s_mac[3], local_s_mac[4], local_s_mac[5]);
	
	struct sockaddr_in inaddr2;
	inet_pton(AF_INET, parsedData.remoteIP, &inaddr2.sin_addr.S_un.S_addr);
	desip = (inaddr2.sin_addr);

	GetMacAddress(remote_s_mac, desip);
	printf("MAC address of remote machine: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", remote_s_mac[0], remote_s_mac[1], remote_s_mac[2], remote_s_mac[3], remote_s_mac[4], remote_s_mac[5]);

	printf("\nlistening on %s...\n", device->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	unsigned long source = inet_addr(parsed.localIP);
	unsigned long dest = inet_addr(parsed.remoteIP);
	
	ethernet_hdr outer_ether_hdr;
	update_ethernet_header(&outer_ether_hdr,local_s_mac,remote_s_mac);

	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header,&pkt_data)) >= 0)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;
	
		/* First Extract Original Header */
		ip_header originalHeader;
		memcpy(&originalHeader, &pkt_data[FRAME_LENGTH], IP_HEADER);
		
		ip_header ip;
		update_ip_header(&ip,source, dest);
				
		if ((originalHeader.proto != (PROTO)) && (pkt_data[FRAME_LENGTH] == VER))
		{
			unsigned short originalLength = ((originalHeader.tlen & 0xFF00) >> 8) | ((originalHeader.tlen & 0x00FF) << 8);
			unsigned short newGreLength = originalLength + IP_HEADER + GRE_HEADER;
			ip.tlen = ((newGreLength & 0xFF00) >> 8) | ((newGreLength & 0x00FF) << 8);
			ip.identification = ((ip.identification & 0xFF00) >> 8) | ((ip.identification & 0x00FF) << 8);
			ip.flags_fo = ((ip.flags_fo & 0xFF00) >> 8) | ((ip.flags_fo & 0x00FF) << 8);

			/* Calculate IPv4 checksum */
			memcpy(&cal_crc[0], &ip, IP_HEADER);
			ip.crc = htons(CalculateIPChecksum(cal_crc));

			memcpy(&mirror_pkt_data[0], &outer_ether_hdr, sizeof(ethernet_hdr));
			memcpy(&mirror_pkt_data[FRAME_LENGTH], &ip, sizeof(ip));
			memcpy(&mirror_pkt_data[FRAME_LENGTH + sizeof(ip)], &gre_header_data, GRE_HEADER);
			memcpy(&mirror_pkt_data[sizeof(ip) + GRE_HEADER + FRAME_LENGTH], &pkt_data[FRAME_LENGTH], header->caplen - FRAME_LENGTH);

			if (pcap_sendpacket(adhandle, &mirror_pkt_data[0], header->caplen + IP_HEADER + GRE_HEADER)>0)
			{
				printf("Error sending Packet : %d", WSAGetLastError());
			}
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

/* Function to print all available interfaces*/
void showDevicesList()
{
	/* Declare and initialize variables */
	DWORD dwRetVal = 0;

	// Set the flags to pass to GetAdaptersAddresses
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

	// default to unspecified address family (both)
	ULONG family = AF_INET;

	LPVOID lpMsgBuf = NULL;

	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 0;
	ULONG Iterations = 0;
	int i = 0;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

	// Allocate a 15 KB buffer to start with.
	outBufLen = WORKING_BUFFER_SIZE;

	do {

		pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
		if (pAddresses == NULL) {
			printf
				("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
			exit(1);
		}

		dwRetVal =
			GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			FREE(pAddresses);
			pAddresses = NULL;
		}
		else {
			break;
		}

		Iterations++;

	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

	if (dwRetVal == NO_ERROR) {
		// If successful, output some information from the data we received
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			printf("\n");
			printf("%d. %wS \n", ++i, pCurrAddresses->FriendlyName);
			printf("%wS\n", pCurrAddresses->Description);
			printf("%s\n", pCurrAddresses->AdapterName);
			pCurrAddresses = pCurrAddresses->Next;
		}
	}
	else {
		printf("Call to GetAdaptersAddresses failed with error: %d\n",
			dwRetVal);
		if (dwRetVal == ERROR_NO_DATA)
			printf("\tNo addresses were found for the requested parameters\n");
		else {

			if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				// Default language
				(LPTSTR)& lpMsgBuf, 0, NULL)) {
				printf("\tError: %s", lpMsgBuf);
				LocalFree(lpMsgBuf);
				if (pAddresses)
					FREE(pAddresses);
				exit(1);
			}
		}
	}

	if (pAddresses) {
		FREE(pAddresses);
	}
}

