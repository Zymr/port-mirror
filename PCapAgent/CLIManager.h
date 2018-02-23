#ifndef CLIMANAGER_H_   
#define CLIMANAGER_H_
#include "stdbool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DELIM "."

//struct to define cli parameters
typedef struct cliParams {
	char* localIP;
	char* remoteIP;
	char* filter;
	int   interfaceNumber;
	bool  displayInterfaces;
	bool  isCaptureCmd;
	bool  isValidCmd;
}tParsedData;

bool isInterface; // bool to check if interface argument is present in CLI cmd.
bool isLocalIP; // bool to check if local IP argument is present in CLI cmd.
bool isRemoteIP; // bool to check if remote IP argument is present in CLI cmd.
tParsedData parsedData; // variable of struct type cliParams1.

/** Parse CLI cmd and returns t_parsedData structure
 *
 * This function returns tParsedData structure.
 *
 * @param[in]   int argc		   arguments count.
 * @param[in]   char* argv[]	   arguments array.
 *
 * @return		tParsedData 	structure of tParsedData type
 */
tParsedData parseCLI(int argc, char* argv[]);

/** Check for valid IP
*
* This function checks if the passed string is valid IP.
*
* @param[in]   char* ip_str	   ip address string is passed.
*
* @return		int 	returns 0 on Success and -1 on failure.
*/
int is_valid_ip(char *ip_str);

/** Check for valid number
*
* This function checks if the passed string is valid number.
*
* @param[in]   char* ip_str	   number string is passed.
*
* @return		int 	returns 0 on Success and -1 on failure.
*/
int valid_digit(char *ip_str);

/*
 * This function is printing the help description.
 */
void usage();
#endif