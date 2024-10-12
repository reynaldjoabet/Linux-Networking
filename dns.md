```sh
ip netns exec dhcp-r dnsmasq --interface=tap-r --dhcp-range=10.50.50.10,10.50.50.100,255.255.255.0
```

```sh
# runs only a dhcp server
# uses --port=0 to disable dns
# 192.168.192.10  as both dns server and gateway
dnsmasq --no-daemon --port=0 --dhcp-range=192.168.192.11,192.168.192.250,1h --dhcp-option=6,192.168.192.10 --dhcp-option=3,192.168.192.10 


## As a DNS server only
dnsmasq --no-daemon --port=5353

## To get a list of options one can pass to --dhcp-option, use dnsmasq --help dhcp. This gives you a list of numbers and their associated options
#Dhcp options are specified using --dchp-option argument indicating the option number or option name and the value

# dnsmasq --dhcp-option=<option number>,<value>

dnsmasq --dhcp-option=3,10.1.1.1 # set router to 10.1.1.1

dnsmasq --dhcp-option=router,10.1.1.1 # set router to 10.1.1.1
```



A dns query is sent to a dns resolver..This dns resolver could be from an isp or from popular dns providers like cloudflare, google.
- If the dns resolver does  not have the answer in its cache, it finds the right authoritative nameserver
- The authoritative nameserver holds the answer
- When we update a domain's dns records as a site owner, we are updating its authoritative nameserver

## How does the dns resolver find the authoritative name server?
- Root Nameservers: Stores the ip addresses of the TLD nameservers(magic of anycast)
- Top level domains(TLD) Nameservers: Store the ip addresses of the authoritative nameservers for all the domains under them( eg `.com`,`.org`,`.net`,`.edu`,`.de`,`.au` etc)
- Authoritatve Nameservers: Provide authoritative answers to dns queries

When you register a domain, the registrar holds the authoritative nameserver by default

DNS Zone-- a database  eg netflix.com containing records

ZoneFile.. the file storing the zone on disk

Name servers(NS) .. a DNS server which hosts 1 or morezones  and stores 1 or more zonefiles.. It is the name server for netflix.com zone that responds to queries about the ip address of netflix.com

Authoritative... Contains real or genuine records

MX.. Mail Excange. it directs email to a mail server

Lowest priority value will be used in MX records
CName(Canonical Name ) record maps one domain name to another. This can prove convenient when running multiple services from a single ip address eg bar.example.com-> foo.example.com

Unlike CName records, A records map domain names to Ip addresses ( bar.example.com->68.50.174.90)

TXT(text) records help with domain verification and email spamming prevention(spf)

MX record should not point to a CName, it should point to an A record


you buy a domain, then point it to a web server
when you install postgres, it will create a user called `postgres`

peer authentication uses the username you are login as and tries to connect to a database with that name

### MAC OS
- To list all available network services:

`networksetup -listallnetworkservices`


- Listing all network hardware ports
`networksetup -listallhardwareports`

- Get current network information
`networksetup -getinfo <networkservice>`
example `networksetup -getinfo Wi-Fi`


## Configuring Wi-Fi
- Join a Wi-Fi network:
`networksetup -setairportnetwork <device> <SSID> <password>`

example `networksetup -setairportnetwork en0 "MyWiFi" "mypassword"`


- List available Wi-Fi networks:
`networksetup -listpreferredwirelessnetworks <device>`



### Setting DNS servers

- Get DNS servers:
`networksetup -getdnsservers <networkservice>`
Example `networksetup -getdnsservers Wi-Fi`

- Set DNS servers:

`networksetup -setdnsservers <networkservice> <dns1> <dns2>`
example `networksetup -setdnsservers Wi-Fi 8.8.8.8 8.8.4.4`

- Reset to automatic DNS:

`networksetup -setdnsservers <networkservice> "Empty"`


### Setting static IP

- Set manual IP address, subnet mask, and router:

`networksetup -setmanual <networkservice> <IP> <subnet> <router>`

`networksetup -setmanual Wi-Fi 192.168.1.100 255.255.255.0 192.168.1.1`

### Configuring Proxy settings

- Set HTTP Proxy:
`networksetup -setwebproxy <networkservice> <server> <port>`

`networksetup -setwebproxy Wi-Fi proxy.example.com 8080`

- Set HTTPS Proxy:

`networksetup -setsecurewebproxy <networkservice> <server> <port>`

`networksetup -setsecurewebproxy Wi-Fi proxy.example.com 8080`

- Disable proxy:
```
networksetup -setwebproxystate <networkservice> off
networksetup -setsecurewebproxystate <networkservice> off

```

[dns-settings](https://alexn.org/wiki/dns-settings/)

[routers-forwarding-mac-address](https://www.baeldung.com/cs/routers-forwarding-mac-address)

what is the difference between flyway core and Flyway Database PostgreSQL or Flyway MySQL

