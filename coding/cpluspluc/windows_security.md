# Windows Security
## SIDS
- SID = Identifiers for identities executing actions (principals)
- Example: `S-1-5-211180699209-877415012-3182924384-1004`
	- `S` = Indicated that this is a SID
	- `1` = SID specification version number
	- `5` = Identifier authority
	- `211180699209-877415012-3182924384` = Domain or local computer identifier
	- `1004` = Relative ID
- Any group or user that was manually created (i.e., not included in Windows by default) will have a Relative ID of 1000 or greater.
- Wel known SID's
	 - Windows defines some built in SIDs
		 - `IsWellKnownSid` function, `WELL_KNOWN_SID_TYPE` enumeration
	 - `S-1-1-0`  = Everyone - all users
	 - `S-1-2-0` = Local - users who log on physically
	 - `S-1-5-18` = Local System- Local system account
	 - `S-1-5-20` = Network Service - Network service account
	 - `S-1-5-19` = Local Service - Local service account
	 - `S-1-5-32-544` = Administrators - Administrators group
- Check which SIDS are logged onto the system. Open registry and open `HKEY_USERS`

## Access Token
- Access token = Kernel object indentifying the security context of a process or thread
	- Process token is called *Primary Token*
	- Thread token is called *Impersonation Token*
- Describes priviliges, accounts, groups associated with the process/thread
- Lsass creates initial token representing the logging user and hand it to *WinLogon*
- Can create a token with the `LogonUser` function
	- Or with one stroke, call `CreateProcessWithLogonW`

### Getting tokens
- With a process handle open with at least `PROCESS_QUERY_INFORMATION`
	- Call `OpenProcessToken` to obtain the token
- With a thread handle open with at least `THREAD_QUERY_INFORMATION`
	- Call `OpenThreadToken` to obtain the token

## Getting token information
- The `GetTokenInformation` API
	- Many token information classes available
	- Token handle must be open with `TOKEN_QUERY` access mask
- The `SetTokenInmformation` API
- Other, more specific API's: `AdjustTokenPrivileges`

## Privileges
- The right of an account to perform some system-level operation. [Microsoft's Documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- Stored in the access token
- The command `whoami /priv` lists the privileges of the current user/process.
- Administrators can use Active Directory or the Local Security Policy Editor to grant or remove privileges. (Local Policies --> User Rights Assignment)
- Most privileges are disabled by default. Must enable before utilization. This is used as a precaution so privileges are not used by mistake
	- Certain API's check if a privilege exists and enabled before allowing operations to proceed.
- Commonly abused privileges: [link](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
	1.  `SeBackupPrivilege` - This privilege causes the system to grant all read access control to any file, regardless of the [_access control list_](https://msdn.microsoft.com/library/windows/desktop/ms721532#-security-access-control-list-gly) (ACL) specified for the file.  
	    Attacker Tradecraft: Collection.
	2.  `SeCreateTokenPrivilege` - Required to create a primary token.  
	    Attacker Tradecraft: Privilege Escalation
	3.  `SeDebugPrivilege`  - Required to debug and adjust the memory of a process owned by another account.  
	    Attacker Tradecraft: Privilege Escalation; Defense Evasion; Credential Access
	4.  `SeLoadDriverPrivilege` - Required to load or unload a device driver.  
	    Attacker Tradecraft: Persistence; Defense Evasion
	5.  `SeRestorePrivilege`  - Required to perform restore operations. This privilege causes the system to grant all write access control to any file, regardless of the ACL specified for the file.  
	    Attacker Tradecraft: Persistence; Defense Evasion
	6.  `SeTakeOwnershipPrivilege` - Required to take ownership of an object without being granted discretionary access.  
	    Attacker Tradecraft: Persistence; Defense Evasion; Collection
	7.  `SeTcbPrivilege` - This privilege identifies its holder as part of the trusted computer base. Some trusted protected subsystems are granted this privilege.  
	    Attacker Tradecraft: Privilege Escalation

## Security descriptors
- An Object is created with a Security Descriptor, this determines who can do what with that object.
- When a caller requests access to an object, the object manager checks with the security system if the caller can obtain a handle to the object
- Exists out of:
	- Owner SID
	- Discretionary Access Control List (DACL)
		- Specifies who has what access to the object
	- System Access Control List (SACL)
		- Specifies which operations by which users should be logged in the security audit log
- Access Control List contains:
	- Header
	- Zero or more Access Control Entry (ACE) structures
		- Each ACE Contains a SID and an Access Mask
-   Determining Access (Simplified)
	- If the object has no DACL (NULL) then it has no protection - The access is allowed
	- If the caller has the take-ownership privilege, then a write-access is granted
	- If the caller is the owner of the object, then a read-control and write DACL access is granted
	- Each ACE in the DACL is examined from first to last
		- If an access allowed for that SID is present, access is granted to the object with the relevant access mask
		- If an access denied for that SID is present, access is denied to the object
		- if the end of the DACL is reached, access is denied
- Security Descriptor Definition Language (SDDL)
	- Is formatted like:
		- `O:owner_sidG:group_sidD:dacl_flags(string_ace1)(string_ace2)…(string_acen)S:sacl_flags(string_ace1)(string_ace2)…(string_acen)`
	- Example:
		- `O:S-1-5-21-3800247982-3998391507-3990260446-1001G:S-1-5-21-3800247982-3998391507-3990260446-513D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-3800247982-3998391507-3990260446-1001)`
	- Check [Link](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) for ACE type, ACE Flags, Permissions explanation and syntax!

## User Account Control (AUC)
- Not a security boundary
	- Can be easily bypassed [Link to bypasses](https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Evasion.md#uac-bypass)
- Goal was running applications with standard user rights and not as administrator
- Allows applications to elevate to administrator rights when needed
- Has different levels which can be changed in "User Account Control Settings"

## Elevation
- Running a process elevated
	- Right click and select "Run as Administrator"
	- Call the `ShellExecuteEx` API with the `runas` verb
	- Add manifest file requesting administratitive rights

## Integrity Levels
- Three levels: `System` (Highest), `High`, `Medium`, `Low`
	- Represented as SIDS
	- Not all processes running with the same user necessarily have the same power
- Integrity level is called "Mandatory Integrity Control" in the access token
	- Running as Standard User sets integrity level to `Medium`
	- Running as Administrator sets integrity level to `High`
	- Services running under one of the 3 service accounts have integrity level of `System`
- There is no write up. `Low` cant write to `Medium` for example.

## Launching Processes
- Launching a process with a different user
	- `CreateProcessAsUser`, requires the `SeAssignPrimaryToken` privilege, mostly usefull from a service
	- `CreateProccessWithLogonW`, requires no special privileges, user must be allowed to log on interactively
- Launching a process elevated
	- Call `ShellExecute` or `ShellExecuteEx`
