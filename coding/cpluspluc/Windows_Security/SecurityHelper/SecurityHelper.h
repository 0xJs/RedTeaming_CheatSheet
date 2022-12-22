#pragma once

#include <string>

std::wstring SidToString(const PSID sid);
PSID StringToSid(PCWSTR sidAsString);
std::wstring SidToUserName(const PSID sid);
std::wstring PrivilegeToString(LUID& luid);
bool EnablePrivilege(PCWSTR name, bool enable);
std::wstring SecurityDescriptorToString(PSECURITY_DESCRIPTOR sd, 
	DWORD parts = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);