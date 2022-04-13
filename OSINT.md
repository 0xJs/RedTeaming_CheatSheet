# OSINT
- The page is bare, really need to do a OSINT course ;)

## DNS
#### Get IP Adresses of a domain name
```
dig <DOMAIN> +short
```

#### Check whois op each IP
- Check who owns the IP, where is it hosted?
```
whois <IP>
```

## Mail
#### Check spf, dkim, dmarc etc
- https://github.com/BishopFox/spoofcheck
```
./spoofcheck.py <DOMAIN>
```

### Email adresses
#### Discovering email adresses or pattern
- https://hunter.io
- https://phonebook.cz

#### Verify email-adres
- https://tools.emailhippo.com/
- https://email-checker.net/validate

## Breached credentials
- https://www.dehashed.com/

#### Check for hashes
- https://hashes.org

## Hunting subdomains
- Script that uses multiple tools to enumerate subdomains: https://github.com/Gr1mmie/sumrecon
#### Amass - Best tool
- https://github.com/OWASP/Amass
```

```

#### Dnsdumpster
- Gui tool: https://dnsdumpster.com/

#### Sublister
```
sublister -domain <DOMAIN>
```

#### crt.sh
- https://crt.sh

#### Dnscan
- https://github.com/rbsec/dnscan
```
dnscan.py <DOMAIN>
```

## Discover Website Technologies
- https://builtwith.com/
- https://addons.mozilla.org/nl/firefox/addon/wappalyzer/

#### Whatwheb
```
whatweb <URL>
```

## Google fu / dorks
- https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06

#### Example
```
site:hackdefense.com filetype:pdf
```


