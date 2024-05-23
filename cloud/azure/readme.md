# Azure-cheatsheet

# Index
* [General](#General)
* [Authenticated enumeration](Authenticated-enumeration.md)
* [Privilege Escalation & Exploitation](privilege-escalation.md)
* [Defense Evasion](defense-evasion.md)
* [Lateral Movement](lateral-movement.md)
* [Persistence](persistence.md)
* [Post exploitation](post-exploitation.md)

# General
- List of Microsoft portals https://msportals.io/
- Great resources
  - https://pentestbook.six2dez.com/enumeration/cloud/azure
  - https://github.com/Kyuu-Ji/Awesome-Azure-Pentest
  - https://github.com/dafthack/CloudPentestCheatsheets/blob/master/cheatsheets/Azure.md
- List of tools https://www.pwndefend.com/2023/01/11/tools/

#### Save Credentials
```
$creds = get-credential

$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USERNAME>', $password)
```

#### Find a specific file
```
Get-Childitem -Path C:\ -Force -Include <FILENAME OR WORD TO SEARCH> -Recurse -ErrorAction SilentlyContinue
```

#### Get company branding
- Browse to URL `https://login.microsoftonline.com/?whr=dhl.com` and replace dhl.com with company domain

## PSSession
#### Save pssession in variable
```
$sess = New-PSSession -Credential $creds -ComputerName <IP>
```

#### Run commands on machine
```
Invoke-Commannd -ScriptBlock {COMMAND} -Session $sess
```

#### Load script on machine
```
Invoke-Commannd -Filepath <PATH TO SCRIPT> -Session $sess
```

#### Copy item through PSSession
```
Copy-Item -ToSession $sess -Path <PATH> -Destination <DEST> -verbose
```
