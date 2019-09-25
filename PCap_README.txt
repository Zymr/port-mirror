
==============================================================================================
	CONTENTS
==============================================================================================

  1.  Overview

  2.  Development and Build Environment.

  
==============================================================================================


==============================================================================================
  		1. Overview
==============================================================================================
   The ReadMe File in this document is for Zymr PCapAgent.exe.
   The Release-Code-Package includes the Microsoft Visual studio Solution and Source files
           
  
==============================================================================================
  		2. Development and Build Environment.
==============================================================================================

   Below is the procedure to setup the development environment.

   a) The Include Directory path in the visual studio should be set to the Include path in 
	  WinPCap developers pack.It can be downloaded from the following link:
	  https://www.winpcap.org/devel.htm
	  
   b) The Library directory path should be set to the Lib path in WinPCap developers pack.
	  Add libraries wpcap.lib,Packet.lib and Ws2_32.lib in Linker->Input->Additional Dependencies
   
   c) Add Preprocessor HAVE_REMOTE,WPCAP in C/C++ -> Preprocessor -> Preprocessor definition
   
   c) Run the executable and can try following commands
      <executable name> -help

      sample commands :
	  <executable name> -help   
	  <executable name> -interfaces
	  <executable name> -i <interfaces> -l <local ip> -r <remote ip> -f <"filter expression">
	  
	  eg.:
	 
	 PCapAgent.exe -help
	 PCapAgent.exe -interfaces
 	 PCapAgent.exe -i 2 -l 192.168.10.1 -r 192.168.10.10
	 PCapAgent.exe -i 2 -l 192.168.10.1 -r 192.168.10.10 -f "dst 192.168.10.34"
	 
	 Filter expressions:
	 -f "src 192.168.10.3"
	 -f "dst 192.168.10.3"
	 -f "src port 43"
	 -f "dst port 43"
	 -f "tcp"
	 
	     
==============================================================================================  
