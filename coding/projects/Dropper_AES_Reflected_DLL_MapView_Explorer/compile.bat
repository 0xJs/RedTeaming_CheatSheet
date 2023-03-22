@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /SUBSYSTEM:WINDOWS /MACHINE:x64 /OUT:implant.exe
del *.obj