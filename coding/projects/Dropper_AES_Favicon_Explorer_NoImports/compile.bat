@ECHO OFF
rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /SUBSYSTEM:WINDOWS /MACHINE:x64 /OUT:implant.exe resources.o
del *.obj