#include <Windows.h>
#include <stdio.h>
#include "..\SecurityHelper\SecurityHelper.h"

void DisplayTokenInfo(HANDLE hToken);

int main(int argc, const char* argv[]) {
    EnablePrivilege(SE_DEBUG_NAME, true);

    DWORD pid = 0, tid = 0;
    HANDLE hObject = nullptr;
    HANDLE hToken = nullptr;

    if (argc == 1) {
        printf("Usage: token [pid | tid]\n"); 
        printf("Using current process\n");
        pid = ::GetCurrentProcessId();
        hObject = ::GetCurrentProcess();
    }
    else {
        pid = atoi(argv[1]);
        hObject = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hObject && ::GetLastError() != ERROR_ACCESS_DENIED) {
            tid = pid;
            pid = 0;
            hObject = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        }
    }
    if (!hObject) {
        printf("Error opening process/thread (%u)\n", ::GetLastError());
        return 1;
    }

    if (tid) {
        printf("Thread IDL %u\n", tid);
        if (!::OpenThreadToken(hObject, TOKEN_QUERY, TRUE, &hToken) && ::GetLastError() != ERROR_ACCESS_DENIED) {
            tid = 0;
            pid = ::GetProcessIdOfThread(hObject);
            ::CloseHandle(hObject);
            printf("Thread is not impersonating... going to the process (%u)\n", pid);
            hObject = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        }
    }

    if (pid) {
        printf("Process ID: %u\n", pid);
        ::OpenProcessToken(hObject, TOKEN_QUERY, &hToken);
    }

    if (!hToken) {
        printf("Error opening token (%u)\n", ::GetLastError());
    }

    printf("Token opened successfully!\n");
    DisplayTokenInfo(hToken);
    ::CloseHandle(hToken);

    return 0;
}

LONGLONG LuidToNumber(LUID& luid) {
    return *(ULONGLONG*)&luid;
}

void DisplayTokenInfo(HANDLE hToken) {
    TOKEN_STATISTICS stats;
    DWORD len;
    if (::GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &len)) {
        printf("Token type: %s\n", stats.TokenType == TokenPrimary ? "Primary" : "Impersonation");
        printf("Token ID: 0x%08llX\n", LuidToNumber(stats.TokenId));
        printf("Groups: %u\n", stats.GroupCount);
        printf("Priveleges: %u\n", stats.PrivilegeCount);
    }

    BYTE buffer[1 << 12];
    if (::GetTokenInformation(hToken, TokenUser, buffer, sizeof(buffer), &len)) {
        auto user = (TOKEN_USER*)buffer;
        printf("User: %ws \n", SidToUserName(user->User.Sid).c_str());
    }

    if (::GetTokenInformation(hToken, TokenGroups, buffer, sizeof(buffer), &len)) {
        auto groups = (TOKEN_GROUPS*)buffer;
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            printf("Group: %ws\n", SidToUserName(groups->Groups[i].Sid).c_str());
        }
    }

    if (::GetTokenInformation(hToken, TokenPrivileges, buffer, sizeof(buffer), &len)) {
        auto privs = (TOKEN_PRIVILEGES*)buffer;
        for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
            auto& p = privs->Privileges[i];
            printf("Privilege name: %ws (%s)\n", PrivilegeToString(p.Luid).c_str(),
                (p.Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled");
        }
    }
}
