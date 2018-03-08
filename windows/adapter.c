#include "adapter.h"

/* Load dll */
void loadiphlpapi() 
{
	HINSTANCE hDll = LoadLibrary("iphlpapi.dll");
		
	GetAdaptersInfo1 = (pgetadaptersinfo)GetProcAddress(hDll,"GetAdaptersInfo");
	if(GetAdaptersInfo1==NULL)
	{
		printf("Error in iphlpapi.dll%d",GetLastError());
	}

	SendArp = (psendarp)GetProcAddress(hDll, "SendARP");
	
	if(SendArp==NULL)
	{
		printf("Error in iphlpapi.dll%d",GetLastError());
	}
}

/* Get the mac address of a given ip */
void GetMacAddress(unsigned char *mac, IN_ADDR destip)
{
	DWORD ret;
	IN_ADDR srcip;
	ULONG MacAddr[2];
	ULONG PhyAddrLen = 6;  /* default to length of six bytes */

	srcip.s_addr = 0;

	//Send an arp packet
	ret = SendArp(destip, srcip, MacAddr, &PhyAddrLen);

	//Prepare the mac address
	if (PhyAddrLen)
	{
		BYTE *bMacAddr = (BYTE *)& MacAddr;
		for (int i = 0; i < (int)PhyAddrLen; i++)
		{
			mac[i] = (char)bMacAddr[i];
		}
	}
}