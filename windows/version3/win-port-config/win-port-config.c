#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <Shlobj.h>
#include "Cli_Manager.h"

#pragma comment(lib,"iphlpapi.lib")			//Link with iphlpapi.lib
#pragma comment(lib,"ws2_32.lib")			//Link with winsock
#pragma comment(lib,"wpcap.lib")			//Link with winpcap

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

void showDevicesList();

int main(int argc, char* argv[])
{
	config_parameters config;

	config = parse(argc, argv);

	if (!config.isValidCmd)
	{
		return -1;
	}
	if (!config.isCaptureCmd)
	{
		return -1;
	}
	if (config.displayInterfaces)
	{
		showDevicesList();
		return 0;
	}
	if (config.stopService)
	{
		if (!(system("sc query win-port-service | find \"RUNNING\"")))
		{
			system("sc stop win-port-service");
			printf("Service stopped\n");
		}
		else
		{
			printf("Service already stopped\n");
		}
		return 0;
	}

	TCHAR maxPath2[300];
	TCHAR iniPath2[300];
	TCHAR diectoryPath[300];

	SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, maxPath2);
	sprintf(diectoryPath, "%s\\WinPortMirror", maxPath2);
	CreateDirectory(diectoryPath, NULL);
	sprintf(iniPath2, "%s\\config.ini", diectoryPath);
	
	
	FILE *fp = fopen(iniPath2, "w+");
	if (fp == NULL)
	{
		printf("Cannot open file");
		exit(1);
	}
	TCHAR maxPath[1024];
	TCHAR NPath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, NPath);
	
	fprintf(fp, "%s\n", config.guid);
	fprintf(fp, "%s\n", config.localIP);
	fprintf(fp, "%s\n", config.remoteIP);
	if (config.filter == NULL)
		fprintf(fp, "");
	else
	  fprintf(fp, "%s\n", config.filter);
	fclose(fp);
	

	if (!(system("sc query win-port-service")))				//returns 0 means service present.
	{
		if (!(system("sc query win-port-service | find \"RUNNING\"")))
		{
			system("sc stop win-port-service");
		}
		system("sc delete win-port-service");
	}
	
	sprintf(maxPath, "sc create win-port-service binPath= \"%s\\win-port-service.exe\" start= delayed-auto", NPath);
	system(maxPath);
	system("sc start win-port-service");

	return 0;
}

/* Function to print all available interfaces*/
void showDevicesList()
{
	
	DWORD dwRetVal = 0;
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
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