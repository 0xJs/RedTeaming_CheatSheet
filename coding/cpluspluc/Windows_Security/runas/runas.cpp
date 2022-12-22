#include <Windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3) {
        printf("Usage: runas <[domain\\]username <\"commandline\">\n");
            return 0;
    }

    printf("Password: ");
    WCHAR password[64];
    _getws_s(password);

    PCWSTR domain = L".";
    PCWSTR username = argv[1];
    auto backslash = wcschr(argv[1], L'\\');
    if (backslash) {
        domain = argv[1];
        *backslash = L'\0';
        username = backslash + 1;
    }

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!::CreateProcessWithLogonW(username, domain, password,
        LOGON_WITH_PROFILE, nullptr, argv[2], 0, nullptr, nullptr,
        &si, &pi)) {
            printf("Error launching process (%u)\n", ::GetLastError());
            return 1;
    }

    printf("Launched process %u\n", pi.dwProcessId);

    ::CloseHandle(pi.hProcess);
    ::CloseHandle(pi.hThread);
    return 0;
}
