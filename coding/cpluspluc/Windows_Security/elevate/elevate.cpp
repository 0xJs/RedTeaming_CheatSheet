#include <Windows.h>
#include <stdio.h>
#include <string>

int main(int argc, const wchar_t* argv[])
{
    if (argc < 2) {
        printf("Usage: elevate <executable> [arguments] ... \n");
        return 0;
    }

    std::wstring params;
    for (int i = 2; i < argc; i++) {
        params += argv[i];
        params += L" ";
    }

    HINSTANCE hInstDll = ::ShellExecute(nullptr, L"runas", argv[1], params.c_str(), nullptr, SW_SHOWDEFAULT);
    if (HandleToLong(hInstDll) < 32) {
        printf("Error launching process (%u)\n", ::GetLastError());
    }
    return 0;
}

