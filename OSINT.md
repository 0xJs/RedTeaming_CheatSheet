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

### Check for subdomains
#### Dnscan
- https://github.com/rbsec/dnscan
```
dnscan.py <DOMAIN>
```

#### Dnsdumpster
- Gui tool: https://dnsdumpster.com/

## Mail
#### Check spf, dkim, dmarc etc
- https://github.com/BishopFox/spoofcheck
```
./spoofcheck.py <DOMAIN>
```
