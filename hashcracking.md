# Hashcracking
## Sources
- Great resource/course: https://in.security/technical-training/password-cracking/
- https://github.com/hashcat/hashcat
- Rules
  - https://github.com/hashcat/hashcat/blob/master/rules/dive.rule
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
  - `--idenitfy` identify the hash
  - `--benchmark` run a benchmark
  - `--speed-only` Use for benchmarks to get a more acurate speed
  - `-O` Enable optimized kernels (limits password length) - Makes hashcat a bit faster for me
  - `-w3` Enable a specific workload profile High (1 = low, 2 = default, 3 = high, 4 = nightmare)
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
hashcat -a 3 -m <HASH TYPE> <HASH FILE> -1 ?u?l -2 ?d?s ?1?1?1?1?1?1?2?2
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
- Will combine all rules of file 1 with rules of file 2. Will increase the cracking time significant. For example use dive + best64
```
hashcat -a 0 -m <HASH TYPE> <HASH FILE> <WORDLIST> -r <RULE FILE> -r <RULE FILE>
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
hashcat -a 6 -m <HASH TYPE> <HASH FILE> <WORDLIST> <MASK>
hashcat -a 7 -m <HASH TYPE> <HASH FILE> <MASK> <WORDLIST>

hashcat -a 6 -m <HASH TYPE> <HASH FILE> <WORDLIST> ?a?a?a --increment
hashcat -a 7 -m <HASH TYPE> <HASH FILE> ?a?a?a <WORDLIST> --increment
```

#### Best effort - Base loop
- You can crack at `9.56` GH/s for a 95^8 keyspace. `95^8 / 9.56 GH/s = 693,954 secs = ~8 days`
- If you have only 8 hours for example, which is 28,800 seconds. `9.56 GH/s * 28,800 seconds = 275,328,000,000,000` needed in 8 hours
- `275,328,000,000,000 (1/8) = 64`
- Then execute with hashcat with `-t 64` to use the top 64 chars (markov)

#### Keyboard walk
- https://github.com/hashcat/kwprocessor

```
kwp -z basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route > keymap.txt

hashcat -a 0 -m <HASH TYPE> <HASH FILE> keymap.txt

hashcat -a 0 -m <HASH TYPE> <HASH FILE> keymap.txt -r dive.rule
```

#### Target specific wordlist generation
- https://www.kali.org/tools/cewl/

```
cewl -d 2 -e -v -w wordlist.txt <URL TARGET>

hashcat -a 0 -m <HASH TYPE> <HASH FILE> wordlist.txt
```

### Combinator attack
#### Combinator two words
- Passphrases, with for example Top 10k / 20k words https://github.com/first20hours/google-10000-english
```
hashcat -a 1 -m <HASH TYPE> <HASH FILE> 20k.txt 20k.txt
```

#### Combinator 3 or 4 words
```
/usr/lib/hashcat-utils/combinator.bin 20k.txt 20k.txt > 20k-combined.txt

hashcat -a 1 -m <HASH TYPE> <HASH FILE> 20k-combined.txt 20k-combined.txt
```

#### Add spaces
```
awk '{print $0" "}' 20k.txt > 20k-space.txt

/usr/lib/hashcat-utils/combinator.bin 20k-space 20k.txt > 20k-combined-mid-space.txt
```

#### Rules
- `-j` apply single rule to the left. `-k` apply single rule to the right
```
hashcat -a 1 -m <HASH TYPE> <HASH FILE> -a1 20k-combined-mid-space.txt -j '$ ' 20k.txt
hashcat -a 1 -m <HASH TYPE> <HASH FILE> -a1 20k-combined-mid-space.txt -j '$ ' 20k-combined-mid-space.txt
```

```
awk '{print $0" "}' 20k-combined-mid-space.txt > 20k-combined-mid-end-space.txt

/usr/lib/hashcat-utils/combinator.bin 20k-combined-mid-end-space.txt 20k-combined-mid-space.txt | hashcat -a 1 -m <HASH TYPE> <HASH FILE> -r dive.rule
```

### Loopback attack
- Generate a wordlist of the potfile and run them again with rules
```
awk -F ":" '{print $NF}' < hashcat.potfile > potfile.list

hashcat -a 0 -m <HASH TYPE> <HASH FILE> -r dive.rule --loopback
```

### Expander attack
- Split candidates into single chars, mutates & recondstructs
- Needs to be recompiled with LEN_MAX 8 and only use unique output
- https://github.com/hashcat/hashcat-utils

```
./expander < woprdlist.txt | sort -u > wordlist_expander.txt
```

### Fingerprint attack
- https://hashcat.net/wiki/doku.php?id=fingerprint_attack
- Expand previously cracked passwords, combo the resulting file with itself, update (expand) wordlist, rinse and repeat

```
awk -F ":" '{print $NF}' < hashcat.potfile | ./expander | sort -u > word.list
hashcat -m <HASH TYPE> <HASH FILE> --remve -a 1 word.list word.list -o word.list2
awk -F ":" '{print $NF}' < word.list2 | ./expander | sort -u > word.list3
hashcat -m <HASH TYPE> <HASH FILE> --remve -a 1 word.list3 word.list3 -o word.list4
```

### Prince attack
- https://hashcat.net/wiki/doku.php?id=princeprocessor
```
./pp.bin word.list --pw-min=8 | hashcat -m <HASH TYPE> hashes.txt
```

#### Prinception
```
./pp.bin word.list --pw-min=8 | ./pp.bin word.list --pw-min=8 | hashcat -m <HASH TYPE> hashes.txt -g 300000
```
