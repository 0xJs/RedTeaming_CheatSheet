# Domain Enumeration
* [General](#General)
* [Powerview Domain](#Powerview-Domain)
* [Powerview Users, groups and computers](#Powerview-users-groups-and-computers) 
* [Powerview Shares](#Powerview-shares)
* [Powerview GPO](#Powerview-GPO)
* [Powerview OU](#Powerview-OU)
* [Powerview ACL](#Powerview-ACL)
* [Powerview Domain Trust](#Powerview-Domain-Trust)
* [Bloodhound](#Bloodhound)

## General
- https://github.com/ropnop/kerbrute
#### Enumerate usernames
```
./kerbrute_linux_amd64 userenum -d <DOMAIN.LOCAL> --dc <IP> usernames.txt
```

#### Bruteforce users
```
/kerbrute_linux_amd64 bruteuser -d <DOMAIN.LOCAL> --dc <IP> rockyou.txt username
```

## Powerview Domain
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
```
. ./PowerView.ps1
```

#### Get current domain
```
Get-Domain
```

#### Get object of another domain
```
Get-Domain -Domain <DOMAIN NAME>
```

#### Get Domain SID for the current domain
```
Get-DomainSID
```

#### Get the domain password policy
```
Get-DomainPolicy
Get-DomainPolicyData
(Get-DomainPolicy)."System Access"
net accounts /domain
```

## Powerview users groups and computers
#### Get Information of domain controller
```
Get-DomainController
Get-DomainController | select-object Name
```

#### Get information of users in the domain
```
Get-DomainUser
Get-DomainUser -Username <USERNAME>
```

#### Get list of all users
```
Get-DomainUser | select samaccountname
```

#### Get list of usernames, last logon and password last set
```
Get-DomainUser | select samaccountname, lastlogon, pwdlastset
Get-DomainUser | select samaccountname, lastlogon, pwdlastset | Sort-Object -Property lastlogon
```

#### Get list of usernames and their groups
```
Get-DomainUser | select samaccountname, memberof
```

#### Get list of all properties for users in the current domain
```
Get-Userproperty -Properties pwdlastset
```

#### Get descripton field from the user
```
Find-UserField -SearchField Description -SearchTerm "built"
Get-DomainUser | Select-Object samaccountname,description
```

#### Get computer information
```
Get-DomainComputer
Get-DomainComputer -FullData
Get-DomainComputer -Computername <COMPUTERNAME> -FullData
```

#### Get computers with a specific Operating System ""
```
Get-DomainComputer -OperatingSystem "*<VERSION*"
```

#### Get list of all computer names and operating systems
```
Get-DomainComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion
```

#### List all groups of the domain
```
Get-DomainGroup
Get-DomainGroup -Domain <DOMAIN>
```

#### List all groups with `*admin*` in there name
```
Get-DomainGroup -GroupName *admin*
```

#### Get all the members of a group
```
Get-DomainGroupMember -Groupname "<GROUP>" -Recurse
```

#### Get the group membership of a user
```
Get-DomainGroup -Username <SAMACCOUNTNAME>
```

#### List all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetLocalGroup -Computername <COMPUTERNAME> -ListGroups
```

#### Get Member of all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetLocalGroupMember -Computername <COMPUTERNAME> -Recurse
Get-NetLocalGroupMember -ComputerName <COMPUTERNAME -GroupName <GROUPNAME>
```

#### Get actively logged users on a computer (needs local admin privs)
```
Get-NetLoggedon -Computername <COMPUTERNAME>
```

#### Get locally logged users on a computer (needs remote registry rights on the target)
```
Get-LoggedonLocal -Computername <COMPUTERNAME>
```

#### Get the last logged users on a computer (needs admin rights and remote registary on the target)
```
Get-LastLoggedOn -ComputerName <COMPUTERNAME>
```

## Powerview shares
#### Find shared on hosts in the current domain
```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```

#### Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```

#### Get all fileservers of the domain
```
Get-NetFileServer
```

## Powerview GPO
#### Get list of GPO's in the current domain
```
Get-DomainGPO
```

#### Get GPO of a specific computer
```
Get-DomainGPO -Computername <COMPUTERNAME>
```

#### Get GPO's which uses restricteds groups or groups.xml for interesting users
```
Get-DomainGPOLocalGroup
```

#### Get users which are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity <COMPUTERNAME>
```

#### Get machines where the given user is member of a specific group
```
Get-DomainGPOUserLocalGroupMapping -Identity <SAMACCOUNTNAME> -Verbose 
```

#### Get GPO applied on an OU.
- Read GPOname from gplink attribute from ```Get-DomainOU```
```
Get-DomainGPO -Identity '{<ID>}'
```

#### Get users which are in a local group of a machine in any OU using GPO 
```
(Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping
```

#### Get users which are in a local group of a machine in a particular OU using GPO
```
(Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{GetDomainComputer -SearchBase $_} | GetDomainGPOComputerLocalGroupMapping
```

## Powerview OU
#### Get OU's in a domain
```
Get-DomainOu -Fulldata
```

#### Get machines that are part of an OU
```
Get-DomainOu <OU> | %{Get-DomainComputer -ADSPath $_}
```

## Powerview ACL
#### Get the ACL's associated with the specified object
```
Get-DomainObjectAcl -Identity <SAMACCOUNTNAME> -ResolveGUIDS
```

#### Get the ACL's associated with the specified prefix to be used for search
```
Get-DomainObjectAcl -ADSprefix ‘CN=Administrator,CN=Users’ -Verbose
```

#### Get the ACLs associated with the specified LDAP path to be used for search
```
Get-DomainObjectAcl -Searchbase "LDAP://CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local" -ResolveGUIDs -Verbose
````

#### Get the ACL's associated with the specified path
```
Get-PathAcl -Path "\\<DC>\sysvol"
```

#### Search for interesting ACL's
```
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl

#New Powerview
Find-InterestingDomainAcl -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl
```

#### Search of interesting ACL's for the current user
```
Find-InterestingDomainAcl | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
```

## Powerview Domain trust
#### Get a list of all the domain trusts for the current domain
```
Get-DomainTrust
```

#### Get details about the forest
```
Get-Forest
```

#### Get all domains in the forest
```
Get-ForestDomain
Get-forestDomain -Forest <FOREST NAME>
```

#### Get global catalogs for the current forest
```
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest <FOREST NAME>
```

#### Map trusts of a forest
```
Get-ForestTrust
Get-ForestTrust -Forest <FOREST NAME>
Get-ForestDomain -Verbose | Get-DomainTrust
```

## BloodHound
https://github.com/BloodHoundAD/BloodHound
```
cd Ingestors
. ./sharphound.ps1
Invoke-Bloodhound -CollectionMethod all -Verbose
Invoke-Bloodhound -CollectionMethod LoggedOn -Verbose

#Copy neo4j-community-3.5.1 to C:\
#Open cmd
cd C:\neo4j\neo4j-community-3.5.1-windows\bin
neo4j.bat install-service
neo4j.bat start
#Browse to BloodHound-win32-x64 
Run BloodHound.exe
#Change credentials and login
```
