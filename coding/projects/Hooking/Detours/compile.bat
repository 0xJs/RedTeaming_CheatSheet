@ECHO OFF

cl.exe /nologo /W0 hookem.cpp /MT /link /DLL detours\lib.X64\detours.lib /OUT:hookem.dll

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp hookme.cpp /link /OUT:hookme.exe /SUBSYSTEM:CONSOLE
del *.obj *.lib *.exp