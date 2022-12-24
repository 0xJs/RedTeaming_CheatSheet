# Getting caught
Page is still being built.
- https://www.youtube.com/watch?v=qIbrozlf2wM


## OPSEC Stuff
#### Shell commands
- `cmd.exe`, `powershell.exe`, `/bin/sh` etc.
- Two flavours: One-off execution `cmd /c <COMMAND>` or spawn once, attach to standard `in/out/error`
- Commands such as `whoami`, `hostname`, `net <COMMAND>`, `ipconfig`, `netstat`, `netsh`, `route`, `tasklist`, `wmic`, `systeminfo`. Especially when ran in a short amount of time.
- Monitoring: Sysmon process create
- Alternative: Leverages OS / Language API's - Don't mostly spawn processes, Use for example "Native" C2 commands.

#### Kerberoasting
- Enumerate all users in the domain where serviceprincipal is not null. It will roast every single user.
- Watch out for honeypot accounts, kerberoasting multiple users, requesting service tickets for services which the user haven't used before.
- Watch the attributes, `serviceprincipalname` does the `SPN` makes sense?, `AdminCount`, `Whencreated`, `Description`, `Groups`, `pwdlastset`, `logoncount`
- Monitoring: Event 4769
- Alternative: Manually enumerate potential targets and kerberoast only specific users.

#### Pass the hash / NTLM auth
- Mimikatz `sekurlsa::pth` patches lsass.
- Monitoring: Touching lsass, NTLM authentication in itself
- Alternative: Use hashes through socks proxy with `wmiexec.py`

#### Overpass the hash
- With Rubeus requesting TGT and TGS
- Monitoring: Event 4768 with encryption type 0x17 (rc4), NTLM authentication!
- Alternative: Use `aes256_hmac` keys
- OPSEC: Mimikatz can also perform overpass the hash, but in a way that writes into LSASS.  Rubeus' method doesn't touch LSASS but it does generate Kerberos traffic from an anomalous process, as this usually only occurs from LSASS. "pick your poison".

#### DCSync
- Sync replication only occurs between domain controllers
- Monitoring: 
- Alternative: Don't DCSync from a non DC. Shadowcopy ntds.dit

#### Key takeaways
- API's are good, shell commands are bad
- Patching lsass is bad, if NLTM auth is required use a pivot/proxy, otherwise use kerberos
- NTLM = bad, AES = good
- Only DCSync from a DC
