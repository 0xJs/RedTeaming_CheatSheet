# Recon

* [Manually](#Manually)
* [AADinternals](#AADinternals)
* [Microburst](#Microburst)
* [Valid emails](#Valid-emails)

### Manually
#### Get if tenant is in use and if fedaration is in use.
- Federation with Azure AD or O365 enables users to authenticate using on-premises credentials and access all resources in cloud.
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
https://login.microsoftonline.com/getuserrealm.srf?login=root@defcorphq.onmicrosoft.com&xml=1
```

#### Get the Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
https://login.microsoftonline.com/defcorphq.onmicrosoft.com/.well-known/openid-configuration
```

### AADinternals
https://github.com/Gerenios/AADInternals
https://o365blog.com/aadinternals/
#### Import the AADinternals module
```
import-module .\AADInternals.psd1
```

####  Get tenant name, authentication, brand name (usually same as directory name) and domain name
```
Get-AADIntLoginInformation -UserName <RANDOM USER>@<DOMAIN>
```

#### Get tenant ID
```
Get-AADIntTenantID -Domain <DOMAIN>
```

#### Get tenant domains
```
Get-AADIntTenantDomains -Domain <DOMAIN>
```

#### Get all the information
```
Invoke-AADIntReconAsOutsider -DomainName <DOMAIN>
```

## Microburst
#### Enumerate used services
- https://github.com/NetSPI/MicroBurst
- Edit the permutations.txt to add permutations such as career, hr, users, file and backup
```
Import-Module MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base <SHORT DOMAIN NAME> -Verbose
```

#### Enumerate Azureblobs
- add permutations to permutations.txt like common, backup, code in the misc directory.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
```

## Valid emails
#### Check for Email ID's
- https://github.com/LMGsec/o365creeper
- Could gather list of emails from something like harvester or hunter.io or smth and validate them!
- admin, root, test, contact (try those default for exam)
```
python o365creeper.py -f list_of_emails.txt -o validemails.txt
```
- Possible to use https://github.com/nyxgeek/onedrive_user_enum (Non-lab-tool)


