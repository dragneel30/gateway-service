#pragma once


#include "networkUtils.h"
#include <iostream>



DWORD GetSessionIdOfUser(PCWSTR, PCWSTR);
BOOL CreateInteractiveProcess(DWORD, PWSTR, BOOL, DWORD, DWORD *);



int shellExecute(const std::wstring& file, const std::wstring& command);
std::wstring wstrWithNewline(const std::wstring& wstr);
std::string strFromWchar(WCHAR* wchar);
std::string strFromWStr(const std::wstring& wstr);
std::wstring wstrFromWchar(const WCHAR* wchar);
std::wstring wstrFromWchar(WCHAR* wchar);
std::string* split(const std::string& str, const std::string& delimeter, int size); 
WCHAR* wcharFromString(const std::string& str);
std::wstring wstrFromString(const std::string& str);

template<typename T>
void freePtarr(T* ptr)
{
   delete[] ptr;
   ptr = nullptr;
}

template<typename T>
void freePtr(T* ptr)
{

  delete ptr;
  ptr = nullptr;
}
