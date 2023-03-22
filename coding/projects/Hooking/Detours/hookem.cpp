// author: reenz0h(twitter : @SEKTOR7net)
#include <stdio.h>
#include <windows.h>
#include "detours.h"
#pragma comment(lib, "user32.lib")

// pointer to original MessageBox
int (WINAPI * pOrigMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBox;
BOOL Hookem(void);
BOOL UnHookem(void);

// Hooking function
int HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	
	printf("HookedMessageBox() called.\n");
	
	pOrigMessageBox(hWnd, "Messagebox is hooked!", "HOOKED!", uType);
	
	return IDOK;
}

// Set hooks on MessageBox
BOOL Hookem(void) {

    LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pOrigMessageBox, HookedMessageBox);
	err = DetourTransactionCommit();

	printf("MessageBox() hooked! (res = %d)\n", err);
	
	return TRUE;
}

// Revert all changes to original code
BOOL UnHookem(void) {
	
	LONG err;
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pOrigMessageBox, HookedMessageBox);
	err = DetourTransactionCommit();

	printf("Hook removed from MessageBox() with result = %d\n", err);
	
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			UnHookem();
			break;
	}
	
    return TRUE;
}

