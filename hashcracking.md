# Hashcracking
## Sources
- Great resource/course: https://in.security/technical-training/password-cracking/
- https://github.com/hashcat/hashcat
- Rules
  - https://github.com/stealthsploit/OneRuleToRuleThemStill
- Wordlists
  - https://github.com/danielmiessler/SecLists/tree/master/Passwords  

## Extracting hashes from files
- https://github.com/openwall/john
- Extracing files
  - `androidbackup2john.py`
  - `ethereum2john.py`
  - `keepass2john.py`
  - `office2john.py`
  - `pdf2john.pl`
  - `ssh2john.py`

# Hashcat
## General
- Usefull hashcat flags:
  - `--potfile-path` to supply where to save the potfile of cracked hashes
  -  `--benchmark` run a benchmark
  -  `-O` Enable optimized kernels (limits password length) - Makes hashcat a bit faster for me
  -  `-w3` Enable a specific workload profile, see pool below - Makes hashcat a bit faster for me
  - `--increment` Enable incremental attack when using masks. If supplied `?a?a?a?a?a?a?a?a` it will bruteforce 1 till 8 characters.

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

#### Possible to create own charsets
- Creates `?1` charset with UPPER and lower chars and `?2` with digits and symbols.
```
hashcat -a 3 -m <HASH TYPE> -1 ?u?l -2 ?d?s ?1?1?1?1?1?1?2?2
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
- Used when the minimum passwod length is not high and cracking of hashtype is fast or having a lot of cracking power!
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

#### Hybrid attack
- Mix mask with a wordlist
- `6 Wordlist + Mask`
- `7 Mask + Wordlist`
```
hashcat -a 6 -m <HASH TYPE> <WORDLIST> <MASK>
hashcat -a 7 -m <HASH TYPE> <MASK> <WORDLIST>

hashcat -a 6 -m <HASH TYPE> <WORDLIST> ?a?a?a?a --increment
hashcat -a 7 -m <HASH TYPE> ?a?a?a?a <WORDLIST> --increment
```

## My methodology
- WIP
