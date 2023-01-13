# Hashcracking
## Sources
- Great resource/course: https://in.security/technical-training/password-cracking/
- https://github.com/hashcat/hashcat
- Rules
  - https://github.com/stealthsploit/OneRuleToRuleThemStill
- Wordlists
  - https://github.com/danielmiessler/SecLists/tree/master/Passwords  


# Hashcat
## General
- Usefull hashcat flags:
  - `--potfile-path` to supply where to save the potfile of cracked hashes
  -  `--benchmark` run a benchmark
  -  `-O` Enable optimized kernels (limits password length) - Makes hashcat a bit faster for me
  -  `-w3` Enable a specific workload profile, see pool below - Makes hashcat a bit faster for me

## Most used Hash modes
- Hashcat supports over 300 hash modes.
```
- [ Hash modes ] -
======+===============================
  900 | MD4
    0 | MD5
 3000 | LM
 1000 | NTLM
 5600 | NetNTLMv2
13100 | Kerberos 5, etype 23, TGS-REP
18200 | Kerberos 5, etype 23, AS-REP
 2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2
```

## Charsets
```
- [ Built-in Charsets ] -

  ? | Charset
 ===+=========
  l | abcdefghijklmnopqrstuvwxyz [a-z]
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
  d | 0123456789                 [0-9]
  h | 0123456789abcdef           [0-9a-f]
  H | 0123456789ABCDEF           [0-9A-F]
  s |  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
  a | ?l?u?d?s
  b | 0x00 - 0xff
```

## Attack modes
- Hashcat has multiple attack modes which are used with the `-a` parameter. For example `-a 0`.
```
- [ Attack Modes ] -

  # | Mode
 ===+======
  0 | Straight
  1 | Combination
  3 | Brute-force
  6 | Hybrid Wordlist + Mask
  7 | Hybrid Mask + Wordlist
  9 | Association
```

#### Wordlist attack
```
hashcat -a 0 -m <HASH TYPE> <HASH FILE> <WORDLIST>
```

#### Wordlist + Rules
```
hashcat -a 0 -m <HASH TYPE> <HASH FILE> <WORDLIST> -r <RULE FILE>
```

#### Wordlist + Rules + Rules
- Will combine all rules of file 1 with rules of file 2. Will increase the cracking time significant.
```
hashcat -a 0 -m <HASH TYPE> <HASH FILE> <WORDLIST> -r <RULE FILE>
```

#### Bruteforce 
- Bruteforces 1 till 8 characters. For more characters add an extra `?a`.
```
hashcat -a 3 -m <HASH TYPE> <HASH FILE> ?a?a?a?a?a?a?a?a --increment
```

#### Mask attack
- Use when password elements are known or for bruteforcing well known patterns
- For example: 1 capital letter, 7 lower, 1 digit.
- https://github.com/sean-t-smith/Extreme_Breach_Masks
```
hashcat -a 3 -m <HASH TYPE> <HASH FILE> ?u?l?l?l?l?l?l?l?d

hashcat -a 3 -m <HASH TYPE> <HASH FILE> <MASK FILE>
```

##### Mask attack + Word
- Save the following wordlist as a ruleset and replace `companyname` and `Companyname` with the name of the target.
- Will bruteforce the masks till 5 characters after or before the company name and 3 before & after.
```
companyname?a?a?a?a?a
companyname?a?a?a?a
companyname?a?a?a
companyname?a?a
Companyname?a?a?a?a?a
Companyname?a?a?a?a
Companyname?a?a?a
Companyname?a?a
?a?a?a?a?acompanyname
?a?a?a?acompanyname
?a?a?acompanyname
?a?acompanyname
?a?a?a?a?aCompanyname
?a?a?a?aCompanyname
?a?a?aCompanyname
?a?aCompanyname
?a?a?acompanyname?a?a?a
?a?acompanyname?a?a
?a?a?aCompanyname?a?a?a
?a?aCompanyname?a?a
```

