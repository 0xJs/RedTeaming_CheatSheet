# RedTeaming_CheatSheet
Pentesting / RedTeaming cheatsheet with all the commands and techniques I learned during my learning journey. Will keep it up to date. If you have any recommendations for courses or links or have any questions feel free to dm me on discord. 0xjs#9027

## Index
* [General](#General)
  * [Coding](coding/readme.md)
  * [Open Source Intelligence](OSINT.md)
  * [Python Dependancies](python_dependancies.md)
  * [Windows System Security](windows_security.md)
  * [Hashcracking](hashcracking.md)
* [Infrastructure](infrastructure/readme.md)
  * [Buffer overflow](infrastructure/bufferoverflow.md)
  * [Enumeration](infrastructure/enumeration.md)
  * [Exploitation](infrastructure/exploitation.md)
  * [Privilege Escalation Windows](infrastructure/privesc_windows.md)
  * [Privilege Escalation Linux](infrastructure/privesc_linux.md)
  * [Post Exploitation](infrastructure/pivoting.md#post-exploitation)
  * [Pivoting](infrastructure/pivoting.md)
* [Windows AD](windows-ad/readme.md)
  * [Relaying](windows-ad/relaying.md)
  * [Initial Access](windows-ad/Initial-Access.md)
  * [Host Reconnaissance](windows-ad/Host-Reconnaissance.md)
  * [Host Persistence](windows-ad/Host-Persistence.md)
  * [Local privilege escalation](infrastructure/privesc_windows.md)
  * [Post-Exploitation](windows-ad/Post-Exploitation.md)
  * [Lateral Movement](windows-ad/Lateral-Movement.md)
  * [Domain Enumeration](windows-ad/Domain-Enumeration.md) 
  * [Domain Privilege Escalation](windows-ad/Domain-Privilege-Escalation.md)
  * [Domain Persistence](windows-ad/Domain-Persistence.md)
* [Defense Evasion](defense-evasion/README.md)
  * [General](defense-evasion/General.md)
  * [Endpoint Detection & Response (EDR)](defense-evasion/Endpoint Detection Response (EDR).md)
  * [Sysmon](defense-evasion/Sysmon.md)
  * [Drivers & Driver Attacks](defense-evasion/Drivers & Driver Attacks.md)
  * [WinDbg](defense-evasion/Windbg.md)
  * [LSASS](defense-evasion/LSASS.md)
  * [Evading Static Detection](defense-evasion/Evading Static Detection.md)
  * [PowerShell](defense-evasion/PowerShell.md)
  * [Application Allowlisting](defense-evasion/Application Allowlisting.md)
  * [Microsoft Defender & Firewall](defense-evasion/Microsoft Defender & Firewall.md)
* [Cloud](cloud/readme.md)
  * [Recon \ OSINT](OSINT.md#cloud)
  * [Initial access attacks](cloud/initial-access-attacks.md)
  * [Cloud services](cloud/readme.md)
    * [Azure](cloud/azure/readme.md)
    * [Amazon Web Services](cloud/aws/readme.md)
    * [Google Cloud Platform](cloud/gc/readme.md)
* [C2 Frameworks]()
  * [Cobalt Strike](cobalt-strike.md)
  * [Covenant](covenant.md)
  * [Metasploit](metasploit.md)

# RedTeaming General
- Definition of Red Teaming by Joe Vest and James Tubberville:
> Red Teaming is the process of using tactics, techniques and procedures (TTPs) to emulate a real-world threat, with the goal of measuring the effectiveness of the people, processes and technologies used to defend an environment.
- OPSEC (Operations Security) is a process that identifies critical information to determine if actions can be observed by enemy intelligence, determines if information obtained by adversaries could be interpreted to be useful to them, and then executes selected measures that eliminate or reduce adversary exploitation of critical information. It's generally used to describe the "ease" by which actions can be observed by "enemy" intelligence.

# Sources & Credits
Most of my knowledge is gathered from the following coures, so big thanks to them! If you like a specific topic I would recommend taking the courses from them!

- Cloud: CARTP and CARTE from Altered Security, breaching the cloud from antisyphon, OASP from Cloudbreach, GCRTS from cyberwarfare
- Windows: CRTP, CRTE, PACES from Altered Security, ECPTX from eLearnSecurity and CRTO from ZeroPointSecurity.
- Infra: OSCP, PNPT from TCM Security and Tiberius privesc courses
- OSINT: PNPT Course
- Coding: Pavel Yosifovich & Sektor7 Reenz0h

# Misc
#### C2 frameworks overview
- [Collection of C2 frameworks that leverage legitimate services to evade detection](https://lolc2.github.io/)
- [C2 Matrix](https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc/edit?gid=0#gid=0)

#### Data exfiltration simulation
- https://github.com/FortyNorthSecurity/Egress-Assess

#### Nuget Package Manager dependancies
- Open Tools --> NuGet Package Manager --> Package Manager Settings --> Package Sources
- Add a source. Name `nuget.org` and Source `https://api.nuget.org/v3/index.json`

#### AV / EDR Netblocks for deny listing 
- https://github.com/her0ness/av-edr-urls/blob/main/AV-EDR-Netblocks
