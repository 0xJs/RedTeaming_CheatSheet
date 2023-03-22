@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:VChelper.exe /SUBSYSTEM:WINDOWS /MACHINE:x64
del *.obj