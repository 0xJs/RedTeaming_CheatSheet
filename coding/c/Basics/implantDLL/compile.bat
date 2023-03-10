@ECHO OFF

cl.exe /D_USRDLL /D_WINDLL implantDLL.cpp /MT /link /DLL /OUT:implant.dll
