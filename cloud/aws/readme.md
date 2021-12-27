# Amazon Web Services pentesting cheatsheet
## Index
* [General](#General)
* [Authenticated enumeration](authenticated-enumeration.md )
* [Privilege Escalation](privilege-escalation.md)
* [Lateral Movement](lateral-movement.md)
* [Persistence](persistence.md)
* [Post Exploitation](post-exploitation.md)

## General
### Tools
- https://github.com/RhinoSecurityLabs/pacu

### Pacu

#### Install Pacu
```
sudo apt-get install python3-pip
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
sudo bash install.sh
```

#### Import AWS keys for a specific profile
```bash
import_keys <profile name>
```

#### Detect if keys are honey token keys
```
run iam__detect_honeytokens
```

#### Enumerate account information and permissions
```
run iam__enum_users_roles_policies_groups
run iam__enum_permissions
whoami
```

#### Check for privilege escalation 
```bash
run iam__privesc_scan
```


