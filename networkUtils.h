#pragma once


#include <windows.h>
#include <windef.h>
#include <Dhcpsapi.h>
#include <iostream>
#include <Esent.h>


 // these function are not use anymore since i started powershell script

DWORD ipDwordFromIpString(std::string str, std::string delimeter, int size);
DWORD ipDwordFromIpBytes(BYTE *b);
BYTE* ipByteFromIpString(std::string str, std::string delimeter, int size);
BYTE* macByteFromMacString(std::string strMac, std::string delimeter, int size);
DHCP_CLIENT_UID* createMacFromMacByte(BYTE* ip, BYTE* subnet, BYTE* byteMac);