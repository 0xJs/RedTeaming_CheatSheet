@ECHO OFF

cl.exe /nologo /W0 vcsniff.cpp /MT /link /DLL detours\lib.X64\detours.lib /OUT:vcsniff.dll

del *.obj *.lib *.exp