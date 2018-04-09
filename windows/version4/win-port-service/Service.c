#define HAVE_REMOTE

#include <tchar.h>
#include <winsock2.h>	
#include <stdlib.h>
#include <iphlpapi.h>
#include <Shlobj.h>
#include <pcap.h>

#include "windows.h"
#include "time.h"
#include "stdio.h"
#include "GRE_Encapsulation.h"

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
pcap_t *adhandle = NULL;
struct pcap_pkthdr *header;

u_char *pkt_data = NULL;
u_char mirror_pkt_data[PACKET_SIZE];
u_char cal_crc[IP_HEADER];

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
	const char localIP[IP_BUFF_SIZE];
	const char remoteIP[IP_BUFF_SIZE];
	const char filter[FILTER_BUFF_SIZE];
	const char guid[GUID_BUFF_SIZE];
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
		OutputDebugString(_T(
			"ServiceMain: SetServiceStatus returned error"));
		exit(-1);
	}

	TCHAR maxPath[BUFF_SIZE];
	TCHAR directoryPath[BUFF_SIZE];
	
	// Get ini file path 
	SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, maxPath);
	sprintf(directoryPath, "%s\\WinPortMirror\\config.ini", maxPath);
	
	config input;
	memset(input.filter,0, sizeof(input.filter));

	FILE *infile;
	infile = fopen(directoryPath, "r");
	
	if (infile == NULL)
	{
		fprintf(stderr, "\nError opening file\n");
		OutputDebugString(_T(
				"ServiceMain: Cannot open config.ini file"));
		exit(-1);
	}
	
	if (fscanf(infile, "%s\n", input.guid) != EOF)
	{
		printf("Guid success\n");
	}
	else
	{
		printf("Error in reading guid (%d)\n", GetLastError());
		exit(-1);
	}

	if (fscanf(infile, "%s\n", input.localIP) != EOF)
	{		
			printf("Local IP success\n");
	}
	else
	{
		printf("Error in reading local ip (%d)\n", GetLastError());
		exit(-1);
	}
	
	if (fscanf(infile, "%s\n", input.remoteIP) != EOF)
	{
		printf("Remote IP success\n");
	}
	else
	{
		printf("Error in reading remote ip (%d)\n", GetLastError());
		exit(-1);
	}

	if (fscanf(infile, "%[^\n]", input.filter) != EOF)
	{
		printf("Filter success\n");
	}
	else
	{
		printf("No filter expression (%d)\n", GetLastError());
	}
	fclose(infile);
	
	char ip_addr_l[IP_BUFF_SIZE];
	strcpy(ip_addr_l, input.localIP);
	if (!is_valid_ip(ip_addr_l))
	{
		OutputDebugString(_T(
			"ServiceMain: Enter correct Local IP"));
		exit(-1);
	}

	char ip_addr_r[IP_BUFF_SIZE];
	strcpy(ip_addr_r, input.remoteIP);
	if (!is_valid_ip(ip_addr_r))
	{
		OutputDebugString(_T(
			"ServiceMain: Enter correct Remote IP"));
		exit(-1);
	}

	pcap_if_t *alldevs;
	pcap_if_t *device;
	int interface_num;
	int i = 0;
	
	char errbuf[PCAP_ERRBUF_SIZE];

	struct bpf_program fcode;
	u_int netmask;
	char* interfaceName = NULL;
	char guid[BUFF_SIZE];

	// Retrieve the device list on the local machine
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		OutputDebugString(_T(
					"ServiceMain: Error in pcap_findalldevs"));
		exit(-1);
	}
	
	char prefixToGUID[BUFF_SIZE];
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
		printf("\nNo interfaces found! (%d)\n", GetLastError());
		OutputDebugString(_T(
			"ServiceMain: No interfaces found.Enter correct GUID"));
		exit(-1);
	}

	// Jump to the selected adapter 
	for (device = alldevs, i = 0; i < interface_num - 1; device = device->next, i++);
	interfaceName = device->name;

	// Open the device 
	if ((adhandle = pcap_open(interfaceName,    // name of the device
		CAPLEN,									// portion of the packet to capture			
		PCAP_OPENFLAG_PROMISCUOUS,				// promiscuous mode
		READOUT_TIME,							// read timeout
		NULL,									// authentication on the remote machine
		errbuf									// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		OutputDebugString(_T(
			"ServiceMain: Unable to open the adapter"));
		pcap_freealldevs(alldevs);
		exit(-1);
	}
	
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nNot an Ethernet network.\n");
		OutputDebugString(_T(
			"ServiceMain: Not an ethernet network"));
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
			OutputDebugString(_T(
				"ServiceMain: Unable to compile the packet filter.Check the syntax"));
			pcap_freealldevs(alldevs);
			exit(-1);
		}

		// set the filter 
		if (pcap_setfilter(adhandle, &fcode) < 0)
		{
			fprintf(stderr, "\nError setting the filter.\n");
			OutputDebugString(_T(
				"ServiceMain: Error setting the filter"));
			pcap_freealldevs(alldevs);
			exit(-1);
		}
	}

	u_char local_s_mac[MAC_ADD], remote_s_mac[MAC_ADD];

	ULONG MacAddr[BYT];
	ULONG PhyAddrLen = 6;

	IPAddr Destip, Srcip;
	Srcip = inet_addr(input.localIP);
	Destip = 0;

	DWORD ret = SendARP(Srcip, Destip, MacAddr, &PhyAddrLen);

	if (ret == NO_ERROR)
	{
		if (PhyAddrLen)
		{
			BYTE *bMacAddr = (BYTE *)& MacAddr;
			for (int i = 0; i < (int)PhyAddrLen; i++)
			{
				local_s_mac[i] = (char)bMacAddr[i];
			}
		}
	}
	else 
	{	
		OutputDebugString(_T(
			"ServiceMain: SendARP(MAC) function returned error"));
		printf("Error: MAC address function failed with error: %d", ret);
		switch (ret) 
		{
		case ERROR_GEN_FAILURE:
			OutputDebugString(_T("ERROR_GEN_FAILURE"));
			break;
		case ERROR_INVALID_PARAMETER:
			OutputDebugString(_T("ERROR_INVALID_PARAMETER"));
			break;
		case ERROR_INVALID_USER_BUFFER:
			OutputDebugString(_T("ERROR_INVALID_USER_BUFFER"));
			break;
		case ERROR_BAD_NET_NAME:
			OutputDebugString(_T("ERROR_BAD_NET_NAME_FAILURE"));
			break;
		case ERROR_BUFFER_OVERFLOW:
			OutputDebugString(_T("ERROR_BUFFER_OVERFLOW"));
			break;
		case ERROR_NOT_FOUND:
			OutputDebugString(_T("ERROR_NOT_FOUND"));
			break;
		default:
			printf("\n");
			break;
		}
	}
	printf("\nMAC address of local machine : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", local_s_mac[0], local_s_mac[1], local_s_mac[2], local_s_mac[3], local_s_mac[4], local_s_mac[5]);

	IPAddr Destip2, Srcip2;
	Srcip2 = inet_addr(input.remoteIP);
	Destip2 = 0;

	ret = SendARP(Srcip2, Destip2, MacAddr, &PhyAddrLen);
	if (ret == NO_ERROR)
	{
		if (PhyAddrLen)
		{
			BYTE *bMacAddr = (BYTE *)& MacAddr;
			for (int i = 0; i < (int)PhyAddrLen; i++)
			{
				remote_s_mac[i] = (char)bMacAddr[i];
			}
		}
	}
	else
	{
		OutputDebugString(_T(
			"ServiceMain: SendARP(MAC) function returned error"));
		printf("Error: MAC address function failed with error: %d", ret);
		switch (ret)
		{
		case ERROR_GEN_FAILURE:
			OutputDebugString(_T("ERROR_GEN_FAILURE"));
			break;
		case ERROR_INVALID_PARAMETER:
			OutputDebugString(_T("ERROR_INVALID_PARAMETER"));
			break;
		case ERROR_INVALID_USER_BUFFER:
			OutputDebugString(_T("ERROR_INVALID_USER_BUFFER"));
			break;
		case ERROR_BAD_NET_NAME:
			OutputDebugString(_T("ERROR_BAD_NET_NAME_FAILURE"));
			break;
		case ERROR_BUFFER_OVERFLOW:
			OutputDebugString(_T("ERROR_BUFFER_OVERFLOW"));
			break;
		case ERROR_NOT_FOUND:
			OutputDebugString(_T("ERROR_NOT_FOUND"));
			break;
		default:
			printf("\n");
			break;
		}
	}

	printf("MAC address of remote machine: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", remote_s_mac[0], remote_s_mac[1], remote_s_mac[2], remote_s_mac[3], remote_s_mac[4], remote_s_mac[5]);

	// At this point, we don't need any more the device list. Free it 
	pcap_freealldevs(alldevs);

	source = inet_addr(input.localIP);
	dest = inet_addr(input.remoteIP);

	// Update Ethernet header with Source and Destination MAC address
	update_ethernet_header(&outer_ether_hdr, local_s_mac, remote_s_mac);
	
	// Service stop event
	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_ServiceStopEvent == NULL)
	{
		// Error creating event.Tell service controller to stop and exit
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode = GetLastError();
		g_ServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			printf("SetServiceStatus returned error (%d)\n", GetLastError());
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
		printf("SetServiceStatus returned error (%d)\n", GetLastError());
		OutputDebugString(_T(
			"ServiceMain: SetServiceStatus returned error"));
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
		printf("SetServiceStatus returned error (%d)\n", GetLastError());
		OutputDebugString(_T(
			"ServiceMain: SetServiceStatus returned error"));
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
			printf("SetServiceStatus returned error (%d)\n",GetLastError());
			OutputDebugString(_T(
				"ServiceCtrlHandler: SetServiceStatus returned error"));
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
		OutputDebugString(_T(
			"ServiceCtrlHandler: Capturing packets..."));
		// Retrieve the packets 
		if ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (res == 0)
			{
				// Timeout elapsed 
				continue;
			}
			
			// First Extract Original Header 
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

				// Calculate IPv4 checksum 
				memcpy(&cal_crc[0], &ip, sizeof(ip));
				ip.crc = htons(CalculateIPChecksum(cal_crc));
				
				memset(mirror_pkt_data, 0, sizeof(mirror_pkt_data));
				memcpy(&mirror_pkt_data[0], &outer_ether_hdr, sizeof(ethernet_hdr));
				memcpy(&mirror_pkt_data[FRAME_LENGTH], &ip, sizeof(ip));
				memcpy(&mirror_pkt_data[FRAME_LENGTH + IP_HEADER], &gre_header_data[0], GRE_HEADER);
			
				memcpy(&mirror_pkt_data[IP_HEADER + GRE_HEADER + FRAME_LENGTH], &pkt_data[FRAME_LENGTH], header->caplen - FRAME_LENGTH);
	
				if (pcap_sendpacket(adhandle, &mirror_pkt_data[0], header->caplen + IP_HEADER + GRE_HEADER) != 0)
				{
					printf("Error sending Packet : %d", GetLastError());
				}
				printf("Captured and Encapsulating Packet GRE \n");
			}
		
		}
		if (res == -1)
		{
			OutputDebugString(_T(
				"ServiceCtrlHandler: Error reading the packets"));
			printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
			exit(-1);
		}
	}

	return ERROR_SUCCESS;
}
