// gateway.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "AsioTelnetClient.h"
#include "generalUtils.h"

#include <Http.h>
#include <string>
#include <cstdlib>
#include <Windows.h>
#include <fstream>
#include <memory>
#include <thread>
#include <boost/algorithm/string.hpp>

#pragma comment(lib, "Httpapi.lib")

struct telnet_client
{
	std::unique_ptr<AsioTelnetClient> client;
	bool finished;
};

struct command
{
	std::wstring comm;
	int prompt;
};

struct device_info
{
	std::wstring name;
	std::wstring ip;
	int must_persist;
	std::vector<command> commands;
	std::vector<std::wstring> scopes;
};

enum ERROR_CODE
{
	SUCCESS = 600, FAILED_EDITING = 601, FAILED_DELETING = 602, FAILED_ADDING = 603, ALREADY_EXIST = 604
};


static std::thread* log_creator_thread;
static bool thread_running = true;
static std::vector<device_info*> dev_info;
static std::wstring relativeDir;
static const std::wstring ENV_PREFIX = L"teracableCG_";
static SERVICE_STATUS_HANDLE ssHandle;
static SERVICE_STATUS status;
static std::wstring binPath;
static std::wstring CONFIG_FILE_FULL_PATH;
static const std::wstring CONFIG_FILE = L"config.ini";
static const std::wstring APP_NAME = L"teraCromeGateway";
static const std::wstring SERVICE_DISPLAY_NAME = L"teraCromeGateway";
static const std::wstring SERVICE_NAME = L"teraCromeGateway";
static const std::string help = "teraCromeGateway options: \n \
For starting the services with parameters: \n \
\t -s : HTTP server address.\n \
\t -p : HTTP server port to listen requests to\n \
\t -d : DHCP server address\n \
Ex: teraCromeGateway -s 192.168.1.100 -p 80 -d 192.168.1.123 (Note: not all parameters are required, if a parameter is missing, the last configuration for that parameter will be used) \n \
\t -i : install the service Ex: teraCromeGateway -i \n \
\t -u : uninstall the service \n Ex: teraCromeGateway -u \n \
Note: you can start the service without parameter, the last configuration will be used to fill those parameters. If no parameter in config file you have to config it or the service would not start. \n \
  ";

void load_array_of_info(std::wstring key, std::wstring section, std::vector<std::wstring>& buffer);
ULONG sendResponse(HANDLE reqHandle, HTTP_REQUEST_ID reqId, char* reason, USHORT statusCode);
int readIniData(const std::wstring& key, std::wstring& buffer, const std::wstring& section);
void load_array_of_info(std::wstring key, std::wstring section, std::vector<int>& buffer);
int readIniData(const std::wstring& key, int& buffer, const std::wstring& section);
bool writeIni(const std::pair<std::wstring, std::wstring>& keyval);
std::wstring getEnvironmentalVariable(const std::wstring& name);


//start executing all the device's commands from the configuration where the _scope belongs. 
void do_telnet(std::wstring _scope, std::wstring _mac);
void WINAPI ServiceMain(DWORD dwArgc, PWSTR* pszArgv);



void WINAPI ServiceCtrlHandler(DWORD dwCtrl);

//returns correct device base from scope
device_info* find_device(std::string scope);

//write logs to a file 
bool writeLog(const std::wstring& buffer);

//sets the status of the service (i,e. START, STOP ETC.)
void SetServiceStatus(DWORD newState);

//loads all the device info from configuration file
void load_device_info();

//frees all the resources
void clean();

//create log file base on the date and return its handle
HANDLE create_log();

void create_log_thread_func();

//executes in console
int wmain(int argc, WCHAR* argv[])
{


	if (argc <= 7)
	{
		WCHAR* buffer = new WCHAR[MAX_PATH];
		if (!GetModuleFileName(NULL, buffer, MAX_PATH))
		{
			writeLog(wstrWithNewline(L"get module file name error: " + std::to_wstring(GetLastError())));
			return 0;
		}

		binPath = buffer;
	    relativeDir = binPath.substr(0, binPath.find_last_of('\\')) + L"\\";
		CONFIG_FILE_FULL_PATH = relativeDir + CONFIG_FILE;

		SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);

		if (!scManager)
		{
			writeLog(wstrWithNewline(L"Opening service control database error: " + std::to_wstring(GetLastError())));
			return 0;
		}
		if (argc > 1)
		{
			if (argc == 2)
			{
				if (wstrFromWchar(argv[1]) == L"-i")
				{
					//install
					std::cout << "Starting installation..." << std::endl;
					std::cout << "Creating configuration file...." << std::endl;
					writeIni(std::pair<std::wstring, std::wstring>(L"-d", L"DHCP_SERVER_IP_ADDRESS"));
					writeIni(std::pair<std::wstring, std::wstring>(L"-s", L"HTTP_SERVER_IP_ADDRESS"));
					writeIni(std::pair<std::wstring, std::wstring>(L"-p", L"HTTP_SERVER_PORT"));
					std::cout << "Configuration file created. " << std::endl;
					static SC_HANDLE scService = CreateService(scManager, SERVICE_NAME.c_str(), SERVICE_DISPLAY_NAME.c_str(), SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_SEVERE, binPath.c_str(), NULL, NULL, NULL, NULL, L"");
					
					if (scService)
					{
						std::cout << "The service was successfully installed" << std::endl;
						std::cout << "The service is starting" << std::endl;
						//StartService(scService, NULL, NULL);
						std::cout << "The service was started" << std::endl;
						CloseServiceHandle(scService);
						scService = NULL;

					}
					else
					{
						if (ERROR_ACCESS_DENIED == GetLastError())
						{
							writeLog(wstrWithNewline(L"Service installation failed please run the installer as administrator: " + std::to_wstring(GetLastError())));
							std::cout << "Service installation failed please run the installer as administrator" << std::endl;
						}
						else
						{
							std::cout << "Service installation failed please check the logs for more info: " << std::endl;
							writeLog(wstrWithNewline(L"Service installation failed: " + std::to_wstring(GetLastError())));
						}
					}


					CloseServiceHandle(scManager);
					scManager = NULL;

				}
				else if (wstrFromWchar(argv[1]) == L"-u")
				{
					//uninstall
					std::cout << "Uinstalling..." << std::endl;
					SetServiceStatus(SERVICE_STOP_PENDING);
					shellExecute(L"cmd.exe", L"/C net stop " + SERVICE_NAME);
					SetServiceStatus(SERVICE_STOPPED);
					shellExecute(L"cmd.exe", L"/C sc delete " + SERVICE_NAME);
					std::cout << "The service was successfully uninstalled." << std::endl;
				}
				else if (wstrFromWchar(argv[1]) == L"-s")
				{
					std::cout << "The service is starting..." << std::endl;
					shellExecute(L"cmd.exe", L"/C net start " + SERVICE_NAME);
					std::cout << "The service was started." << std::endl;
				}
				else
				{
					//help
					std::cout << help << std::endl;
				}
			}
			else if (argc <= 7)
			{
				//start service with parameters
				for (int a = 1; a < argc; a += 2)
				{
					std::wstring arg = wstrFromWchar(argv[a]);
					if (arg == L"-s" || arg == L"-p" || arg == L"-d")
					{
						writeIni(std::pair<std::wstring, std::wstring>(arg, argv[a + 1]));
					}
					else
					{
						std::cout << help << std::endl;
					}
				}
			}
			else
			{
				//help
				std::cout << help << std::endl;
			}

		}
		else
		{
			//start using config ini
			DWORD bufferSize = sizeof(SERVICE_NAME);
			WCHAR* serviceName = new WCHAR[bufferSize];
			if (GetServiceKeyName(scManager, SERVICE_DISPLAY_NAME.c_str(), serviceName, &bufferSize))
			{
				SERVICE_TABLE_ENTRY table[] =
				{
					{ const_cast<WCHAR*>(SERVICE_NAME.c_str()), ServiceMain },
					{ NULL, NULL }
				};
				if (!StartServiceCtrlDispatcher(table))
				{
					writeLog(wstrWithNewline(L"Starting service control dispatcher failed. error code: " + std::to_wstring(GetLastError())));
				}
			}
			else
			{
				writeLog(wstrWithNewline(L"The service is not installed yet."));
			}
		}
	}


	std::cout << "Press any key to continue" << std::endl;
	std::cin.get();
	return 0;
}

//executes in service
void onStart(DWORD dwArgc, PWSTR* pszArgv)
{
	log_creator_thread = new std::thread(create_log_thread_func);
	std::wstring dhcpAddress;
	std::wstring httpAddress;
	std::wstring port;

	readIniData(L"-d", dhcpAddress, APP_NAME);
	readIniData(L"-s", httpAddress, APP_NAME);
	readIniData(L"-p", port, APP_NAME);
	load_device_info();

	
	std::wstring fullUrl = L"http://" + httpAddress + L":" + port + L"/";
	HTTPAPI_VERSION version = HTTPAPI_VERSION_2;

	ULONG res = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);

	if (res == NO_ERROR)
	{
		PHANDLE pReqQueueHandle = new HANDLE;

		res = HttpCreateRequestQueue(version, NULL, NULL, 0, pReqQueueHandle);

		std::wstring log;
		if (res == NO_ERROR)
		{
			PHTTP_URL_GROUP_ID pGroupID = new HTTP_URL_GROUP_ID;
			PHTTP_SERVER_SESSION_ID sid = new HTTP_SERVER_SESSION_ID;
			res = HttpCreateServerSession(version, sid, 0);
			if (res == NO_ERROR)
			{
				res = HttpCreateUrlGroup(*sid, pGroupID, 0);
				if (res == NO_ERROR)
				{
					HTTP_BINDING_INFO info;
					info.Flags.Present = 1;
					info.RequestQueueHandle = *pReqQueueHandle;
					res = HttpSetUrlGroupProperty(*pGroupID, HttpServerBindingProperty, &info, sizeof(info));
					if (res == NO_ERROR)
					{
						PCWSTR url = fullUrl.c_str();
						res = HttpAddUrlToUrlGroup(*pGroupID, url, NULL, 0);

						if (res == NO_ERROR)
						{
							ULONG bufferSize = 8096;
							ULONG flag = HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY;
							ULONG bytesReceive;
							HTTP_REQUEST_ID hrid = HTTP_NULL_ID;
							SetServiceStatus(SERVICE_RUNNING);
							while (true)
							{
								bytesReceive = 0;
								PHTTP_REQUEST buffer = new HTTP_REQUEST[bufferSize];

								RtlZeroMemory(buffer, bufferSize);

								res = HttpReceiveHttpRequest(*pReqQueueHandle, hrid, flag, buffer, bufferSize, &bytesReceive, NULL);
								
								if (res == NO_ERROR)
								{
									if (buffer->Verb == HttpVerbPOST)
									{
										if (buffer->pEntityChunks->FromMemory.pBuffer)
										{
											std::string POSTData = (PSTR)(buffer->pEntityChunks->FromMemory.pBuffer);
											log = wstrFromString(POSTData);
											int paramSize = 1;
											for (std::size_t a = 0; a < POSTData.size(); a++)
											{
												if (POSTData[a] == '&')
													paramSize++;
											}

											std::string* map = split(POSTData, "&", paramSize);

											///////////////////////////////////////////////////////////////////embedded powershell script
											std::wstring possibleErrorId = ENV_PREFIX + std::to_wstring(hrid);
											std::wstring scriptVars = L"$macs = '" + relativeDir + L"mac.txt'; $envid = '" + possibleErrorId + L"'; $d = '" + dhcpAddress + L"'; $newip=$null; $g=''; $m=''; $i=''; $n=''; $desc=''; $t=''; $process=''; \n";


											//log vars;

											std::wstring process;
											std::wstring scope;
											std::wstring ip;
											std::wstring mac;
											std::wstring name;
											std::wstring newip;
											for (int a = 0; a < paramSize; a++)
											{
												std::string* keyVal = split(map[a], "=", 2);
												std::wstring val = wstrFromString(keyVal[1]);
												if (wstrFromString(keyVal[0]) == L"s")
													if (val == L"NoAccess")
														scriptVars += L"$" + wstrFromString(keyVal[0]) + L" = '" + val + L".cfg'; ";
													else
														scriptVars += L"$" + wstrFromString(keyVal[0]) + L" = 'DC" + val + L".cfg'; ";

												else
													scriptVars += L"$" + wstrFromString(keyVal[0]) + L" = '" + val + L"'; ";

												if (keyVal[0] == "g") scope = val;
												else if (keyVal[0] == "m") mac = val;
												else if (keyVal[0] == "i") ip = val;
												else if (keyVal[0] == "n") name = val;
												else if (keyVal[0] == "newip") newip = val;
												else if (keyVal[0] == "process") process = val;
												freePtarr(keyVal);
											}
											freePtarr(map);

											std::wstring script = scriptVars + L"\n\
											function isSuccess{\n\
											    if($?)\n\
												{\n\
													return $true; \n\
												}\n\
												else\n\
												{\n\
													return $false; \n\
												}\n\
											}\n\
function addEnv{\n\
Param([String]$p1)\n\
[Environment]::SetEnvironmentVariable($envid, $p1, 'User');\n\
										}\n\
											if ( $process -eq 'ADD' )\n\
												{\n\
													add-dhcpserverv4reservation -ScopeId $g -ClientId $m -IPAddress $i -Name $n -Description $desc  -Type $t -ComputerName $d\n\
													if (isSuccess)\n\
													{\n\
														addEnv('600') \n\
													}\n\
													else\n\
													{\n\
													addEnv('603')\n\
													}\n\
													set-dhcpserverv4optionvalue -OptionId 67 -value $s -ReservedIP $i -ComputerName $d\n\
												}\n\
												ElseIf($process -eq 'EDIT')\n\
											{\n\
											if ($newip -ne $null)\n\
												{\n\
													$client = Get-DhcpServerv4Reservation -ipaddress $i -ComputerName $d\n\
													$optionvalue = Get-DhcpServerv4OptionValue -ReservedIP $i -ComputerName $d \n\
													remove-dhcpserverv4reservation -ipaddress $i -ComputerName $d \n\
													add-dhcpserverv4reservation -ScopeId $client.ScopeId -IPAddress $newip -ClientId $m -name $client.Name -type $client.Type -Description $client.Description -ComputerName $d\n\
													set-dhcpserverv4optionvalue -ReservedIP $newip -optionid 67 -value $optionvalue.value -ComputerName $d \n\
													if (isSuccess -eq $true)\n\
													{\n\
													$client.ClientId | Out-File $macs\n\
														addEnv('600') \n\
													}\n\
													else\n\
													{\n\
													addEnv('601');\n\
													}\n\
																									}\n\
												else\n\
												{\n\
														$client = get-dhcpserverv4reservation -ipaddress $i\n\
																if ($m.length -eq 0)\n\
																{\n\
																	$m = $client.ClientId; \n\
																}\n\
																	if ($n.length -eq 0)\n\
																	{\n\
																		$n = $client.Name; \n\
																	}\n\
																		if ($desc.length -eq 0)\n\
																		{\n\
																			$desc = $client.Description; \n\
																		}\n\
																			if ($t.length -eq 0)\n\
																			{\n\
																				$t = $client.Type; \n\
																			}\n\
															$optionvalues = get-dhcpserverv4optionvalue -ReservedIP $i -ComputerName $d\n\
																				[String]$optionvalue; \n\
																				for ($a = 0; $a -lt @($optionvalues).Count; $a++ )\n\
												   {\n\
																					if ($optionvalues[$a].OptionId -eq 67 -and $s.length -ne 0)\n\
																					{\n\
																						$optionvalues[$a].Value = $s; \n\
																						break; \n\
																					}\n\
												   }\n\
																					set-dhcpserverv4reservation -IpAddress $i -ClientId $m -Name $n -Description $desc -Type $t -ComputerName $d\n\
																						for ($a = 0; $a -lt @($optionvalues).Count; $a++ )\n\
												   {\n\
																							set-dhcpserverv4optionvalue -ReservedIP $i -OptionId $optionvalues[$a].OptionId -Value $optionvalues[$a].Value -ComputerName $d\n\
																		if (isSuccess)\n\
																		{\n\
																			addEnv('600')\n\
																			break\n\
																		}\n\
												   }\n\
												   												   				if (isSuccess -eq $false)\n\
											{\n\
																						addEnv('600')\n\
											}\n\
										}\n\
													\n\
												 }\n\
												ElseIf ( $process -eq 'DELETE' )\n\
												{\n\
												    remove-dhcpserverv4reservation -ScopeId $g -ClientId $m -ComputerName $d\n\
												   	if (isSuccess)\n\
													{\n\
														addEnv('600') \n\
													}\n\
													else\n\
													{\n\
													addEnv('602');\n\
													}\n\
												} \n\
											";
											////////////////////////////////////////////////////////////////////////////////////////////////////////////////
										
											
											int ret = shellExecute(L"powershell.exe", script);
											
										    if (ret > 32)
											{
												writeLog(script);
												int errorCode;
												errorCode = static_cast<ERROR_CODE>(_wtoi(getEnvironmentalVariable(possibleErrorId).c_str()));
												errorCode = 600;
												if (process == L"ADD")
												{
													if (errorCode == SUCCESS)
													{
														writeLog(L"A client named " + name + L" with mac address " + mac + L" has been added and assigned to " + ip + L" IP Address in scope " + scope);
													}
													else
													{
														writeLog(L"Failed to add the client with mac " + mac);
													}
												}
												else if (process == L"EDIT")
												{
													if (errorCode == SUCCESS)
													{
														//writeLog(exit_code);
														
														writeLog(L"A client with mac address " + mac + L" has been edited. new datas: scope = " + scope + L" ip: " + ip + L" mac= " + mac + L" name: " + mac);

														do_telnet(scope, mac);
													}
													else
													{
														writeLog(L"Failed to edit the client with mac address " + mac);
													}
												}
												else if (process == L"DELETE")
												{
													if (errorCode == SUCCESS)
													{
														writeLog(L"A client with mac address " + mac + L" has been deleted");
													}
													else
													{
														writeLog(L"Failed to delete the client with mac " + mac);
													}
												}
												res = sendResponse(*pReqQueueHandle, buffer->RequestId, "test", errorCode);
											}

											
											if (res == NO_ERROR)
											{
												writeLog(L"httpresponse sent!");
											}
											else
											{
												writeLog(std::to_wstring(res));
												writeLog(L"httpresponse fails!");
											}
										}
									}
								}
								else
								{
									writeLog(L"httpreceivehttprequest error: " + std::to_wstring(res));
								}
								if (buffer)
								{
									freePtr(buffer);
								}
								HTTP_SET_NULL_ID(&hrid);
							}
							HttpRemoveUrlFromUrlGroup(*pGroupID, url, HTTP_URL_FLAG_REMOVE_ALL);
						}
						else
						{
							writeLog(wstrWithNewline(L"httpaddurltourlgroup error: " + std::to_wstring(res)));
							SetServiceStatus(SERVICE_STOPPED);
						}
					}
					else
					{
						writeLog(wstrWithNewline(L"httpseturlgroupproperty error: " + std::to_wstring(res)));
						SetServiceStatus(SERVICE_STOPPED);
					}
					HttpCloseUrlGroup(*sid);
				}
				else
				{
					writeLog(wstrWithNewline(L"httpcreateurlgroup error: " + std::to_wstring(res)));
					SetServiceStatus(SERVICE_STOPPED);
				}
				HttpCloseServerSession(*sid);
			}
			else
			{
				writeLog(wstrWithNewline(L"httpcreateserversession: " + std::to_wstring(res)));
				SetServiceStatus(SERVICE_STOPPED);
			}
			HttpCloseRequestQueue(*pReqQueueHandle);
			freePtr(pGroupID);
			freePtr(sid);
		}
		else
		{
			writeLog(wstrWithNewline(L"httpcreaterequestqueue error: " + std::to_wstring(res)));
			SetServiceStatus(SERVICE_STOPPED);
		}
		freePtr(pReqQueueHandle);
	}
	else
	{
		writeLog(wstrWithNewline(L"http driver initialization failed"));
		SetServiceStatus(SERVICE_STOPPED);
	}

}

bool writeLog(const std::wstring& buffer)
{
	std::wstring newBuffer = std::move(buffer + L"\r\n\0");
	HANDLE handle = create_log();
	return WriteFile(handle, newBuffer.c_str(), newBuffer.length() * sizeof(WCHAR), NULL, NULL) == NO_ERROR;
}


void SetServiceStatus(DWORD newState)
{
	status.dwCurrentState = newState;
	if (newState == SERVICE_RUNNING)
		status.dwCheckPoint = 0;
	else if (newState == SERVICE_STOPPED)
	{
		status.dwCheckPoint = 0;
		clean();
	}
	else
		status.dwCheckPoint++;
	SetServiceStatus(ssHandle, &status);
}

void WINAPI ServiceCtrlHandler(DWORD dwCtrl)
{
	status.dwCurrentState = dwCtrl;

	SetServiceStatus(ssHandle, &status);
}


void WINAPI ServiceMain(DWORD dwArgc, PWSTR* pszArgv)
{
	status.dwCheckPoint = 1;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwCurrentState = SERVICE_START_PENDING;

	ssHandle = RegisterServiceCtrlHandler(L"teraCromeGateway", ServiceCtrlHandler);

	if (!ssHandle)
	{
		writeLog(wstrWithNewline(L"RegisterServiceCtrlHandler: " + GetLastError()));
		return;
	}


	onStart(dwArgc, pszArgv);
	
}

bool writeIni(const std::pair<std::wstring, std::wstring>& keyval)
{
	if (!WritePrivateProfileString(L"teraCromeGateway", keyval.first.c_str(), keyval.second.c_str(), CONFIG_FILE_FULL_PATH.c_str()))
	{
		writeLog(wstrWithNewline(L"failed to writeLog log " + std::to_wstring(GetLastError())));
		return false;
	}
	return true;
}

int readIniData(const std::wstring& key, int& buffer, const std::wstring& section)
{
	std::wstring buff;
	int ret = readIniData(key, buff, section);
	buffer = std::stoi(buff);
	return ret;
}

int readIniData(const std::wstring& key, std::wstring& buffer, const std::wstring& section)
{
	DWORD bufferSize = 255;
	WCHAR* tempBuffer = new WCHAR[bufferSize];
	int ret = GetPrivateProfileString(section.c_str(), key.c_str(), NULL, tempBuffer, bufferSize, CONFIG_FILE_FULL_PATH.c_str());
	
	buffer = wstrFromWchar(tempBuffer);
	return ret;
}

void clean()
{
	for (std::size_t a = 0; a < dev_info.size(); a++)
	{
		delete dev_info[a];
		dev_info[a] = nullptr;
	}
	thread_running = false;
	Sleep(1000);
	delete log_creator_thread;
	log_creator_thread = nullptr;
}

device_info* find_device(std::string scope)
{
	for (std::size_t a = 0; a < dev_info.size(); a++)
	{
		if (std::find(dev_info[a]->scopes.begin(), dev_info[a]->scopes.end(), wstrFromString(scope)) != dev_info[a]->scopes.end())
			return dev_info[a];
	}
	return nullptr;
}


void do_telnet(std::wstring _scope, std::wstring _mac)
{
	Sleep(5000);
	std::string scope = strFromWStr(_scope);
	std::string mac = strFromWStr(_mac);

	device_info* found_device = find_device(scope);

	if (!found_device)
	{
		writeLog(L"device with scope " + wstrFromString(scope) + L" cannot be found");
		return;
	}


	boost::asio::io_service io_service;
	tcp::resolver resolver(io_service);
	tcp::resolver::query query(strFromWStr(found_device->ip), "23");
	tcp::resolver::iterator iterator = resolver.resolve(query);
	telnet_client new_client{ std::make_unique<AsioTelnetClient>(io_service, iterator), false };

	std::vector<command>& commands = found_device->commands;
	int reply_counter = 0;
	std::size_t current_command = 0;
	new_client.client->setReceivedSocketCallback([&mac, &commands, &reply_counter, &new_client, &current_command](const std::string& message)
	{
		writeLog(wstrFromString(message));
		if (current_command < commands.size())
		{
			if (reply_counter >= commands[current_command].prompt)
			{
				std::string raw_command = strFromWStr(commands[current_command].comm);
				std::size_t index = raw_command.find("mac");
				if (index != std::string::npos)
					raw_command = raw_command.replace(index, 3, mac);
				for (std::size_t a = 0; a < raw_command.size(); a++)
				{
					new_client.client->write(raw_command[a]);
				}
				new_client.client->write('\n');
				reply_counter = 0;
				current_command++;
			}
			else
			{
				reply_counter++;
			}
		}
		else
		{
			new_client.finished = true;
		}
	});

	while (!new_client.finished) {}

}


ULONG sendResponse(HANDLE reqHandle, HTTP_REQUEST_ID reqId, char* reason, USHORT statusCode)
{
	HTTP_RESPONSE response;
	RtlZeroMemory(&response, sizeof(response));


	response.StatusCode = statusCode;
	response.ReasonLength = (USHORT)strlen(reason);
	response.pReason = reason;
	ULONG bytes;
	ULONG res = HttpSendHttpResponse(reqHandle, reqId, 0, &response, NULL, &bytes, NULL, 0, NULL, NULL);

	USHORT count = 10;

	return res;

}

void load_array_of_info(std::wstring key, std::wstring section, std::vector<std::wstring>& buffer)
{
	std::size_t key_ctr = 1;
	std::wstring val;
	while (true)
	{
		int size = readIniData(key + std::to_wstring(key_ctr), val, section);
		if (size == 0)
			break;
		buffer.push_back(val);
		key_ctr++;
	}
}

void load_array_of_info(std::wstring key, std::wstring section, std::vector<int>& buffer)
{
	std::vector<std::wstring> temp_buffer;
	load_array_of_info(key, section, temp_buffer);
	for (std::size_t a = 0; a < temp_buffer.size(); a++)
	{
		buffer.push_back(std::stoi(temp_buffer[a]));
	}
}
void load_device_info()
{
	std::size_t dev_ctr = 1;
	while (true)
	{
		device_info* new_dev_info = new device_info;
		std::wstring device = L"teraChromeDevice" + std::to_wstring(dev_ctr);
		std::vector<std::wstring> commands;
		std::vector<int> prompts;
		load_array_of_info(L"scope", device, new_dev_info->scopes);
		if (new_dev_info->scopes.size() == 0)
			break;
		load_array_of_info(L"command", device, commands);
		load_array_of_info(L"prompt", device, prompts);
		for (std::size_t a = 0; a < commands.size(); a++)
		{
			new_dev_info->commands.push_back(command{ commands[a], prompts[a] });
		}
		new_dev_info->name = device;
		readIniData(L"ip", new_dev_info->ip, device);
		readIniData(L"must_persist", new_dev_info->must_persist, device);
		dev_info.push_back(new_dev_info);
		dev_ctr++;

	}
	/*
	for (std::size_t a = 0; a < dev_info.size(); a++)
	{
	std::wcout << dev_info[a]->ip << std::endl;
	for (std::size_t b = 0; b < dev_info[a]->scopes.size(); b++)
	{
	std::wcout << dev_info[a]->scopes[b] << std::endl;
	}
	for (std::size_t b = 0; b < dev_info[a]->commands.size(); b++)
	{
	std::wcout << dev_info[a]->commands[b].comm << std::endl;
	std::wcout << dev_info[a]->commands[b].prompt << std::endl;
	}
	std::wcout << dev_info[a]->must_persist << std::endl;
	}
	*/

}

std::wstring getEnvironmentalVariable(const std::wstring& name)
{
	DWORD bufferSize = 255;
	WCHAR* buffer = new WCHAR[bufferSize];
	GetEnvironmentVariable(name.c_str(), buffer, bufferSize);
	writeLog(L"getenvinroenrentelvairlarmelrm");
	SetEnvironmentVariable(name.c_str(), NULL);
	return wstrFromWchar(buffer);
}

HANDLE create_log()
{
	std::cout << "test" << std::endl;
	SYSTEMTIME system_time;
	GetSystemTime(&system_time);
	std::wstring month = L"-";
	std::wstring day = L"-";

	if (system_time.wMonth < 10)
	{
		month += L"0";
	}
	if (system_time.wDay < 10)
	{
		day += L"0";
	}
	std::wstring LOG_FILE = std::to_wstring(system_time.wYear) + month + std::to_wstring(system_time.wMonth) + day + std::to_wstring(system_time.wDay) + L".txt";

	HANDLE handle = CreateFile((relativeDir + LOG_FILE).c_str(), FILE_APPEND_DATA, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	return handle;
}

void create_log_thread_func()
{
	while (thread_running)
	{
		create_log();
	}
}