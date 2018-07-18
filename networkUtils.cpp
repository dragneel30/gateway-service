#include "stdafx.h"
#include "generalUtils.h"
#include <sstream>

DWORD ipDwordFromIpBytes(BYTE *b)
{
    return b[3] + (b[2] << 8) + (b[1] << 16) + (b[0] << 24);
}
BYTE* ipByteFromIpString(std::string str, std::string delimeter, int size)
{
	std::string* strs = split(str, delimeter, size);
	BYTE* ip = new BYTE[size];
	int i = 0;
	while(i < size)
	{
		ip[i] = std::stoi(strs[i]);
		i++;
	}
	return ip;
}


DWORD ipDwordFromIpString(std::string str, std::string delimeter, int size)
{
	return ipDwordFromIpBytes(ipByteFromIpString(str, delimeter, size));
}


DHCP_CLIENT_UID* createMacFromMacByte(BYTE* ip, BYTE* subnet, BYTE* byteMac)
{
	DHCP_CLIENT_UID* mac = new DHCP_CLIENT_UID;
	const std::size_t SIZE = 11;

	mac->Data = new BYTE[SIZE];
	mac->DataLength = sizeof(BYTE) * SIZE;

    mac->Data[0] = ip[3] & subnet[3];
	mac->Data[1] = ip[2] & subnet[2];
	mac->Data[2] = ip[1] & subnet[1];
	mac->Data[3] = ip[0] & subnet[0];
	
	mac->Data[4] = 0x1;

	mac->Data[5] = byteMac[0];
	mac->Data[6] = byteMac[1];
	mac->Data[7] = byteMac[2];
	mac->Data[8] = byteMac[3];
	mac->Data[9] = byteMac[4];
	mac->Data[10] = byteMac[5];

	return mac;
}

BYTE* macByteFromMacString(std::string strMac, std::string delimeter, int size)
{
	std::string* strMacs = split(strMac, delimeter, size);
	
	BYTE* mac = new BYTE[size];
	int i = 0; 

	while(i < size)
	{
		std::stringstream ss;
		ss << std::hex << strMacs[i];
		ss >> mac[i];
		i++;
	}
	
	return mac;
}

