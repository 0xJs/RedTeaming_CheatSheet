// wellknownsids.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include "..\SecurityHelper\SecurityHelper.h"

int main()
{
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    PSID sid = (PSID)buffer;

    for(int i = 0; i < 120; i++) {
        DWORD len = sizeof(buffer);
        if (!::CreateWellKnownSid((WELL_KNOWN_SID_TYPE)i, nullptr, sid, &len))
            continue;

        printf("%3d: %ws (%ws)\n", i, SidToString(sid).c_str(),  SidToUserName(sid).c_str());
    }
    return 0;
}
