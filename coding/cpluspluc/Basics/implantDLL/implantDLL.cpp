#include <Windows.h>
#pragma comment (lib, "user32.lib")


BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
__declspec(dllexport) BOOL WINAPI RunME(void) {
	
	MessageBox(
		NULL,
		"Example DLL!",
		"MessageBox",
        MB_OK
	);
	 
		 return TRUE;
	}
}
