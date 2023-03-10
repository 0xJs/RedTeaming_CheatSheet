@ECHO OFF

cl.exe /O2 /D_USRDLL /D_WINDLL implantDLL.cpp implantDLL.def /MT /link /DLL /OUT:implantDLL.dll