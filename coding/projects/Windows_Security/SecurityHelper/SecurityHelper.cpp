// SecurityHelper.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "SecurityHelper.h"

// function to convert Sid to String
std::wstring SidToString(const PSID sid)
{
	PWSTR stringSid;
	std::wstring result;
	if (::ConvertSidToStringSid(sid, &stringSid)) {
		result = stringSid;
		::LocalFree(stringSid);
	}
	return result;
}

// function to convert String to Sid
PSID StringToSid(PCWSTR sidAsString)
{
	PSID sid = nullptr;
	::ConvertStringSidToSid(sidAsString, &sid);
	return sid;
}

std::wstring SidToUserName(const PSID sid) {
	// Using nullptr to use computer, but could be a DC
	WCHAR name[64], domain[64];
	DWORD lname = _countof(name), ldomain = _countof(domain);

	SID_NAME_USE use;
	if (::LookupAccountSid(nullptr, sid, name, &lname, domain, &ldomain, &use))
		return std::wstring(domain) + L"\\" + name;

	return L"";
}

std::wstring PrivilegeToString(LUID& luid) {
	WCHAR name[64];
	DWORD len = _countof(name);
	if (::LookupPrivilegeName(nullptr, &luid, name, &len))
		return name;
	return L"";
}

bool EnablePrivilege(PCWSTR name, bool enable) {
	LUID luid;
	if (!::LookupPrivilegeValue(nullptr, name, &luid))
		return false;

	HANDLE hToken;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	BOOL ok = ::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	ok = ok && ::GetLastError() == ERROR_SUCCESS;
	::CloseHandle(hToken);
	return ok;
}

std::wstring SecurityDescriptorToString(PSECURITY_DESCRIPTOR sd, DWORD parts)
{
	std::wstring result;
	PWSTR sddl;
	if (::ConvertSecurityDescriptorToStringSecurityDescriptor(sd, SDDL_REVISION, parts, &sddl, nullptr) && sddl) {
		result = sddl;
		::LocalFree(sddl);
	}
	return result;
}
