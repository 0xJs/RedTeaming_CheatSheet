# OSINT
- The page is bare, really need to do a OSINT course ;)

## Search engines
- https://www.google.com/
- https://www.bing.com/
- https://duckduckgo.com/
- https://www.baidu.com/
- https://yandex.com/

### Google fu / dorks
- https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06

#### Example
```
site:hackdefense.com filetype:pdf
```

#### Specific website
```
searchterm site:example.com
```

#### Search for specific string
```
"search this string"
``` 

## Create Sockpuppet / alias
- Settings up a anonymous sockpuppet
- https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/

## Host Information
#### Get IP Adresses of a domain name
```
dig <DOMAIN> +short
```

#### Check whois op each IP
- Check who owns the IP, where is it hosted?
```
whois <IP>
```

### Mail
#### Check spf, dkim, dmarc etc
- https://github.com/BishopFox/spoofcheck
```
./spoofcheck.py <DOMAIN>
```

## Finding Email adresses
#### Discovering email adresses or pattern
- https://hunter.io
- https://phonebook.cz

#### Verify email-adres
- https://tools.emailhippo.com/
- https://email-checker.net/validate

## Hunting usernames
- https://namechk.com/
- https://whatsmyname.app/
- https://namecheckup.com/

## Hunting passwords
- https://www.dehashed.com/
- https://www.weleakinfo.to/
- https://leakcheck.io/
- https://snusbase.com/
- https://scylla.sh/
- https://haveibeenpwned.com/

#### Check for hashes
- https://hashes.org

## Hunting for personal information
- https://www.whitepages.com/
- https://www.truepeoplesearch.com/
- https://www.fastpeoplesearch.com/
- https://www.fastbackgroundcheck.com/
- https://webmii.com/
- https://peekyou.com/
- https://www.411.com/
- https://www.spokeo.com/
- https://thatsthem.com/

### Search phone numbers
- https://www.truecaller.com/
- https://calleridtest.com/
- https://infobel.com/
- Can also check out logins, forget password and check for phone number!

## Web OSINT
### Hunting subdomains
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

## Image OSINT
### Reverse Image Searching
- https://images.google.com/
- https://yandex.com/images/
- https://tineye.com/
- Drag the image in

#### EXIF Data
- Location data is already way more secure, but might still get something.
- http://exif.regex.info/exif.cgi

#### Identifying Geographical Locations
- https://www.geoguessr.com/
- https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/

## Social media OSINT
### Twitter
- https://twitter.com/search-advanced
- https://socialbearing.com/
- https://www.twitonomy.com/
- http://sleepingtime.org/
- https://mentionmapp.com/
- https://tweetbeaver.com/
- http://spoonbill.io/
- https://tinfoleak.com/
- https://tweetdeck.com/

### Facebook
- https://sowdust.github.io/fb-search/
- https://intelx.io/tools?tab=facebook

### Instagram
- https://wopita.com/
- https://codeofaninja.com/tools/find-instagram-user-id/
- https://www.instadp.com/
- https://imginn.com/

### Snapchat
- https://map.snapchat.com

### Reddit
- https://www.reddit.com/search

### Linkedin
- https://www.linkedin.com/
