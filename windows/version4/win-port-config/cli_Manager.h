#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define DELIM "."
#define IP_BUFF_SIZE 32
#define BUFF_SIZE 512
#define L_BUFF_SIZE 1024
#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

typedef struct config_parameters
{
	char *localIP;
	char *remoteIP;
	char *filter;
	char *guid;	
	bool  displayInterfaces;
	bool  isCaptureCmd;
	bool  isValidCmd;
	bool  stopService;
}config_parameters;

bool isInterface;						// bool to check if interface argument is present in CLI cmd.
bool isLocalIP;							// bool to check if local IP argument is present in CLI cmd.
bool isRemoteIP;						// bool to check if remote IP argument is present in CLI cmd.

config_parameters config_para;

// Function to parse command line parameters
config_parameters parse(int argc, char* argv[]);

// Functions for valid ip check
int is_valid_ip(char *ip_str);
int is_digit(char *ip_str);

// Function for help 
void usage();