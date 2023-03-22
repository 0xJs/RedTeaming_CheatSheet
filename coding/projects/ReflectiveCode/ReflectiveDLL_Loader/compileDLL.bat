@ECHO OFF

cl.exe /W0 /D_USRDLL /D_WINDLL *.c *.cpp /MT /link /DLL /OUT:implant.dll
echo Cleaning up...
del *.obj *.lib *.exp