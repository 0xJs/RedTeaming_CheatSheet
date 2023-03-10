@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TcinjectDLL.cpp /link /OUT:injectDLL.exe /SUBSYSTEM:CONSOLE /MACHINE:x64