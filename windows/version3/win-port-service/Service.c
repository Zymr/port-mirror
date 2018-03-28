
#define HAVE_REMOTE

#include <tchar.h>
#include <winsock2.h>	
#include "windows.h"
#include "time.h"
#include "stdio.h"
#include <stdlib.h>
#include <iphlpapi.h>
#include <Shlobj.h>
#include "GRE_Encapsulation.h"

#include <pcap.h>

#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"wpcap.lib")	
#pragma comment(lib,"ws2_32.lib")	

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME _T("win-port-service") 

int res = 1;
pcap_t *adhandle;
struct pcap_pkthdr *header;

u_char *pkt_data;
u_char mirror_pkt_data[2000];
u_char cal_crc[20];

unsigned long source;
unsigned long dest;

ethernet_hdr outer_ether_hdr;

int _tmain(int argc, TCHAR *argv[])
{

	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{ SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};

	if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
	{
		return GetLastError();
	}

	return 0;
}

typedef struct config_parameters
{
	char localIP[100];
	char remoteIP[100];
	char filter[100];
	char guid[200];
}config;


VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	DWORD Status = E_FAIL;

	// Register service control handler with the SCM
	g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

	if (g_StatusHandle == NULL)
	{
		goto EXIT;
	}

	// Initiate service in service controller
	ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwServiceSpecificExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		exit(1);
	}

	TCHAR maxPath2[300];
	TCHAR iniPath2[300];
	TCHAR diectoryPath[300];


	// Get ini file path 
	SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, maxPath2);
	sprintf(diectoryPath, "%s\\WinPortMirror\\config.ini", maxPath2);
	
	config input;
	memset(input.filter, NULL, sizeof(input.filter));

	FILE *infile;
	infile = fopen(diectoryPath, "r");
	
	if (infile == NULL)
	{
		fprintf(stderr, "\nError opening file\n");
		exit(1);
	}
	
	if (fscanf(infile, "%s\n", input.guid) != EOF)
	{
		printf("Guid success\n", WSAGetLastError());
	}
	else
	{
		printf("Error in reading guid\n", WSAGetLastError());
		exit(1);
	}

	if (fscanf(infile, "%s\n", input.localIP) != EOF)
	{
		printf("Local IP success\n", WSAGetLastError());
	}
	else
	{
		printf("Error in reading local ip\n", WSAGetLastError());
		exit(1);
	}
	if (fscanf(infile, "%s\n", input.remoteIP) != EOF)
	{
		printf("Remote IP success\n", WSAGetLastError());
	}
	else
	{
		printf("Error in reading remote ip\n", WSAGetLastError());
		exit(1);
	}
	if (fscanf(infile, "%[^\n]", input.filter) != EOF)
	{
		printf("Filter success\n", WSAGetLastError());
	}
	else
	{
		printf("Error in filter expression\n", WSAGetLastError());
	}
	fclose(infile);

	pcap_if_t *alldevs;
	pcap_if_t *device;
	int interface_num;
	int i = 0;
	
	char errbuf[PCAP_ERRBUF_SIZE];

	struct bpf_program fcode;
	u_int netmask;
	char* interfaceName = NULL;
	char* filter = NULL;
	char guid[400];

	// Retrieve the device list on the local machine
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	char prefixToGUID[200];
	strcpy(prefixToGUID, "rpcap://\\Device\\NPF_");
	strcpy(guid,input.guid);
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
		printf("\nNo interfaces found!\n", WSAGetLastError());
		exit(1);
	}

	if (interface_num < 1 || interface_num > i)
	{
		printf("\n%d:: Interface number out of range.\n", interface_num);
		pcap_freealldevs(alldevs);
		exit(1);
	}

	// Jump to the selected adapter 
	for (device = alldevs, i = 0; i <interface_num - 1; device = device->next, i++);
	interfaceName = device->name;

	// Open the device 
	if ((adhandle = pcap_open(interfaceName,    // name of the device
		1500,									// portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS,				// promiscuous mode
		10000,									// read timeout
		NULL,									// authentication on the remote machine
		errbuf									// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		// Free the device list 
		pcap_freealldevs(alldevs);
		exit(-1);
	}
	
	if (device->addresses != NULL)
		// Retrieve the mask of the first address of the interface 
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		// If the interface is without addresses we suppose to be in a C class network 
		netmask = 0xffffff;

	// compile the filter 
	if (strcmp(input.filter, "") != 0)
	{
		if (pcap_compile(adhandle, &fcode, &input.filter[0], 1, netmask) < 0)
		{
			fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			// Free the device list 
			pcap_freealldevs(alldevs);
			exit(1);
		}


		// set the filter 
		if (pcap_setfilter(adhandle, &fcode) < 0)
		{
			fprintf(stderr, "\nError setting the filter.\n");
			// Free the device list 
			pcap_freealldevs(alldevs);
			exit(1);
		}
	}

	u_char local_s_mac[6], remote_s_mac[6];

	ULONG MacAddr[2];
	ULONG PhyAddrLen = 6;

	IPAddr Destip, Srcip;
	Srcip = inet_addr(input.localIP);
	Destip = 0;

	DWORD ret = SendARP(Srcip, Destip, MacAddr, &PhyAddrLen);
	if (PhyAddrLen)
	{
		BYTE *bMacAddr = (BYTE *)& MacAddr;
		for (int i = 0; i < (int)PhyAddrLen; i++)
		{
			local_s_mac[i] = (char)bMacAddr[i];
		}
	}

	printf("\nMAC address of local machine : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", local_s_mac[0], local_s_mac[1], local_s_mac[2], local_s_mac[3], local_s_mac[4], local_s_mac[5]);

	IPAddr Destip2, Srcip2;
	Srcip2 = inet_addr(input.remoteIP);
	Destip2 = 0;

	ret = SendARP(Srcip2, Destip2, MacAddr, &PhyAddrLen);
	if (PhyAddrLen)
	{
		BYTE *bMacAddr = (BYTE *)& MacAddr;
		for (int i = 0; i < (int)PhyAddrLen; i++)
		{
			remote_s_mac[i] = (char)bMacAddr[i];
		}
	}

	printf("MAC address of remote machine: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", remote_s_mac[0], remote_s_mac[1], remote_s_mac[2], remote_s_mac[3], remote_s_mac[4], remote_s_mac[5]);

	printf("\nlistening on %s...\n", device->description);

	// At this point, we don't need any more the device list. Free it 
	pcap_freealldevs(alldevs);

	source = inet_addr(input.localIP);
	dest = inet_addr(input.remoteIP);

	update_ethernet_header(&outer_ether_hdr, local_s_mac, remote_s_mac);

	// Service stop event
	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_ServiceStopEvent == NULL)
	{
		// Error creating event.Tell service controller to stop and exit
		// Tell service controller we are stopped and exit
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode = GetLastError();
		g_ServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			printf("SetServiceStatus returned error\n", WSAGetLastError());
		}
		goto EXIT;
	}

	// Tell the service controller service is started
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		printf("SetServiceStatus returned error\n", WSAGetLastError());
	}

	// Thread to perform the main task of the service
	HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

	// Wait until worker thread exits signaling that the service needs to stop
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(g_ServiceStopEvent);

	// Tell the service controller we are stopped
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		printf("SetServiceStatus returned error\n", WSAGetLastError());
	}

EXIT:
	return;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode)
	{
	case SERVICE_CONTROL_STOP:

		if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
			break;

		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		g_ServiceStatus.dwWin32ExitCode = 0;
		g_ServiceStatus.dwCheckPoint = 4;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			printf("SetServiceStatus returned error\n", WSAGetLastError());
		}

		// This will signal the worker thread to start shutting down
		SetEvent(g_ServiceStopEvent);

		break;

	default:
		break;
	}
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
	//  Periodically check if the service has been requested to stop
	while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
	{
	
	/* Retrieve the packets */
		if ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (res == 0)
				/* Timeout elapsed */
				continue;

			/* First Extract Original Header */
			ip_header originalHeader;
			memcpy(&originalHeader, &pkt_data[FRAME_LENGTH], IP_HEADER);

			ip_header ip;
			update_ip_header(&ip, source, dest);

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
			exit(1);
		}
	}

	return ERROR_SUCCESS;
}
