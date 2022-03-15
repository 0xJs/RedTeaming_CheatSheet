# OSINT
- The page is bare, really need to do a OSINT course ;)

## DNS
#### Get IP Adresses of a domain name
```
dig cyberbotic.io +short
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
./spoofcheck.py cyberbotic.io
```
