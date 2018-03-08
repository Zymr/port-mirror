#include <winsock2.h>
#include "windows.h"
#include <iphlpapi.h>

#include "time.h"
#include "stdio.h"

#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8

/* Function to load dll*/
void loadiphlpapi();

/* Loads from Iphlpapi.dll */
typedef DWORD(WINAPI* psendarp)(IN_ADDR DestIP, IN_ADDR SrcIP, PULONG pMacAddr, PULONG PhyAddrLen);
typedef DWORD (WINAPI* pgetadaptersinfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen );

psendarp SendArp;
pgetadaptersinfo GetAdaptersInfo1;

/* Function to get MAC address */
void GetMacAddress(unsigned char *mac, IN_ADDR destip);

