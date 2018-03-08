#include "CLIManager.h"
#include <memory.h>

/* parses the CLI arguments and pass the parsed data.*/
tParsedData parseCLI(int argc,char* argv[])
{
	isInterface = false;
	isLocalIP = false;
	isRemoteIP = false;
	parsedData.isValidCmd = true;
	parsedData.isCaptureCmd = false;
	parsedData.displayInterfaces = false;

	// print usage if not any argument is passed in cli
	if (argc == 1)
	{
		usage();
		return parsedData;
	}

	//if the argument passed is 'help'
	if (!strcmp(argv[1], "-help"))
	{
		usage();
		return parsedData;
	}

	if (argc == 2) {

		//if the argument passed is 'interfaces', display the list available interfaces
		if (strcmp(argv[1], "-interfaces") == 0)
		{
			parsedData.isCaptureCmd = true;
			parsedData.displayInterfaces = true;
			return parsedData;
		}
		else
		{
			printf("CLIManager		: Invalid Argument\n");
			usage();
			return parsedData;
		}
	}
	if (argc > 2) {
		//if mandatory commands present, parse the cmd from CLI
		for (int j = 1; j < argc; j += 2)
		{
			switch (argv[j][1])
			{
			case 'g':// guid 
			{
				isInterface = true;

				if ((argv[j + 1] == NULL) || (argv[j + 1][0] == '\0'))
				{
					printf("CLIManager		: GUID parameter missing!\n");
					parsedData.isValidCmd = false;
					return parsedData;
				}
				parsedData.guid = argv[j + 1];
				parsedData.isCaptureCmd = true;
			};
			break;

			case 'l':// local IP
			{
				isLocalIP = true;
				char ip_addr[32];
				strcpy(ip_addr, argv[j + 1]);

				if (is_valid_ip(ip_addr))
				{
					parsedData.localIP = argv[j + 1];
				}
				else
				{
					printf("CLIManager		: Invalid local IP address!\n");
					parsedData.isValidCmd = false;
					return parsedData;
				}
			};
			break;

			case 'r': //remote IP
			{
				isRemoteIP = true;
				char ip_addr[32];
				strcpy(ip_addr, argv[j + 1]);

				if (is_valid_ip(ip_addr))
					parsedData.remoteIP = argv[j + 1];
				else
				{
					printf("CLIManager		: Invalid remote IP address!\n");
					parsedData.isValidCmd = false;
					return parsedData;
				}
			};
			break;

			case 'f': // filter expression
			{
				if ((argv[j + 1] == NULL) || (argv[j + 1][0] == '\0'))
				{
					printf("CLIManager		: Filter expression is missing!\n");
					parsedData.isValidCmd = false;
					return parsedData;
				}
				else
				{
					parsedData.filter = argv[j + 1];
				}
			};
			break;

			default: // if cmd is not proper
			{
				printf("CLIManager		: Not valid expression!\n");
				parsedData.isValidCmd = false;
				return parsedData;
			}
			break;
			}
		}
		//check for the mandatory commands i.e., -i, -l, -r is present
		if (!isInterface || !isLocalIP || !isRemoteIP)
		{
			printf("CLIManager		: Mandatory commands missing.\n");
			usage();
			parsedData.isCaptureCmd = false;
			return parsedData;
		}
	}


	return parsedData;
}

/* return 1 if IP string is valid, else return 0 */
int is_valid_ip(char *ip_str)
{

	int num, dots = 0;
	char *ptr;

	if (ip_str == NULL)
		return 0;

	ptr = strtok(ip_str, DELIM);

	if (ptr == NULL)
		return 0;

	while (ptr) {

		/* after parsing string, it must contain only digits */
		if (!is_digit(ptr))
			return 0;

		num = atoi(ptr);

		/* check for valid IP */
		if (num >= 0 && num <= 255) {
			/* parse remaining string */
			ptr = strtok(NULL, DELIM);
			if (ptr != NULL)
				++dots;
		}
		else
			return 0;
	}

	/* valid IP string must contain 3 dots */
	if (dots != 3)
		return 0;

	return 1;
}

/* return 1 if string contain only digits, else return 0 */
int is_digit(char *ip_str)
{
	while (*ip_str) {
		if (*ip_str >= '0' && *ip_str <= '9')
			++ip_str;
		else
			return 0;
	}
	return 1;
}

/*Printing help description*/
void usage()
{
	printf("\n");
	printf("---------------------------------------------------------------------------\n");
	printf("USAGE\n\n");
	printf("Arguments list \t:\n");
	printf("1. -help				: help\n");
	printf("2. -interfaces				: list of interfaces\n");
	printf("3. -g <interface GUID>			: guid number\n");
	printf("4. -l <local ip>			: local gre tunnel endpoint\n");
	printf("5. -r <remote ip>			: remote gre tunnel endpoint\n");
	printf("6. -f <filter expression>		: filter expression e.g. -f \"src 10.10.10.1\"\n\n");
	printf("<executable> -i <interface> -l <Local IP> -r <Remote IP> -f <\"src ip\">\n\n");


	printf("EXAMPLES\n\n");
	printf("win-port-mirror.exe -help\n");
	printf("win-port-mirror.exe -interfaces\n");
	printf("win-port-mirror.exe -g {58BEB18B-143A-46EC-9BA6-52489ED5F182} -l 1.2.3.4 -r 1.2.3.5\n");
	printf("win-port-mirror.exe -g {58BEB18B-143A-46EC-9BA6-52489ED5F182} -l 1.2.3.4 -r 1.2.3.5 -f \"src 1.1.1.1\"\n");
	printf("win-port-mirror.exe -g {58BEB18B-143A-46EC-9BA6-52489ED5F182} -l 1.2.3.4 -r 1.2.3.5 -f \"src port 20\"\n");
	printf("---------------------------------------------------------------------------\n");
}