#include <Windows.h>
#include <stdio.h>

int main()
{
    printf("Thread ID: %u\n", ::GetCurrentThreadId());

    HANDLE hToken;
    if (!::LogonUser(L"test", L".", L"Welcome123!", LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("Error (%u)\n", ::GetLastError());
        return 1;
    }

    if (::ImpersonateLoggedOnUser(hToken)) {
        // do work as test

        ::RevertToSelf();
    }
    ::CloseHandle(hToken);
    return 0;
}