# Azure-cheatsheet

# Index
* [General](#General)
* [Authenticated enumeration](Authenticated-enumeration.md )
* [Privilege Escalation](privilege-escalation.md)
* [Cloud <-> On-Prem - Lateral Movement](Cloud-OnPrem-lateral-movement.md)
* [Persistence](persistence.md)
* [Post exploitation](post-exploitation.md)

# General
- List of Microsoft portals https://msportals.io/
- Great resources
  - https://pentestbook.six2dez.com/enumeration/cloud/azure
  - https://github.com/Kyuu-Ji/Awesome-Azure-Pentest
  - https://github.com/dafthack/CloudPentestCheatsheets/blob/master/cheatsheets/Azure.md

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
