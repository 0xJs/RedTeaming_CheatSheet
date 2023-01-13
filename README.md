# RedTeaming_CheatSheet
Pentesting / RedTeaming cheatsheet with all the commands and techniques I learned during my learning journey. Will keep it up to date. If you have any recommendations for courses or links or have any questions feel free to dm me on discord. 0xjs#9027

## Index
* [General](#General)
  * [Payloads](payloads.md)
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
  * [Post Exploitation](infrastructure/post_exploitation.md)
* [Windows AD](windows-ad/readme.md)
  * [Relaying](windows-ad/relaying.md)
  * [Initial Access](windows-ad/Initial-Access.md)
  * [Host Reconnaissance](windows-ad/Host-Reconnaissance.md)
  * [Host Persistence](windows-ad/Host-Persistence.md)
  * [Evasion](windows-ad/Evasion.md)
  * [Local privilege escalation](infrastructure/privesc_windows.md)
  * [Post-Exploitation](windows-ad/Post-Exploitation.md)
  * [Lateral Movement](windows-ad/Lateral-Movement.md)
  * [Domain Enumeration](windows-ad/Domain-Enumeration.md) 
  * [Domain Privilege Escalation](windows-ad/Domain-Privilege-Escalation.md)
  * [Domain Persistence](windows-ad/Domain-Persistence.md)
* [Cloud](cloud/readme.md)
  * [Recon \ OSINT](cloud/recon.md)
  * [Initial access attacks](cloud/initial-access-attacks.md)
  * [Cloud services](cloud/readme.md)
    * [Azure](cloud/azure/readme.md)
    * [Amazon Web Services](cloud/aws/readme.md)
    * [Google Cloud Platform](cloud/gcb/readme.md)
* [C2 Frameworks]()
  * [Cobalt Strike](cobalt-strike.md)
  * [Covenant](covenant.md)
  * [Metasploit](metasploit.md)

# RedTeaming General
- Definition of Red Teaming by Joe Vest and James Tubberville:
> Red Teaming is the process of using tactics, techniques and procedures (TTPs) to emulate a real-world threat, with the goal of measuring the effectiveness of the people, processes and technologies used to defend an environment.
- OPSEC (Operations Security) is a process that identifies critical information to determine if actions can be observed by enemy intelligence, determines if information obtained by adversaries could be interpreted to be useful to them, and then executes selected measures that eliminate or reduce adversary exploitation of critical information. It's generally used to describe the "ease" by which actions can be observed by "enemy" intelligence.

# Sources
- Cloud: CARTP from Pentester Academy and breaching the cloud from antisyphon.
- Windows: CRTP, CRTE, PACES from Pentester Academy, ECPTX from eLearnSecurity and CRTO from RastaMouse.
- Infra: OSCP, PNPT from TCM Security and Tiberius privesc courses
- OSINT: PNPT Course

#### Data exfiltration simulation
- https://github.com/FortyNorthSecurity/Egress-Assess
