@ECHO OFF

cl.exe /nologo /W0 vcmigrate.cpp /MT /link /DLL /OUT:vcmigrate.dll

del *.obj