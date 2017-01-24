## Shocens

Query Shodan and Censys 

#### Usage

* Install required gems                 `gem install shodan rest-client ruby_dig`
* Export your Shodan API key            => `export SHODAN_KEY="abcd123"`
* Export your Censys API id             => `export CENSYS_UID="abcd123"`
* Export your Censys API secret         => `export CENSYS_SECRET="abcd123"`

```
Usage: ruby censys.rb [options]
    -o, --shodan-by-org=ORG_NAME     Search Shodan by organization name
    -i, --shodan-by-ips=FILE         Search by IPs in CIDR format separated by newline
                                        Example: 127.0.0.0/24. Note 0 in final octet.
    -f, --censys-by-file=FILE        Search Censys with list of search terms separated by newline
    -q, --censys-query=QUERY         Your censys.io query. Examples: '127.0.0.1' or 'domain.tld'
                                        or 'parsed.extensions=="domain.tld"'
                                        or 'autonomous_system.description:"target"'
                                        See https://censys.io/overview#Examples
    -s, --save-output                Write output to csv file, ip list file, diff file
    -d, --diff-last                  Compare last scan results and update diff file
    -h, --help                       Show this message
```

#### Output

```bash
-> % ruby shocens.rb -o "google"
[+] Beginning Shodan search for google

[+] 698121 results in org:"google"

[!] 6921 pages of results- this could take a while... Ctrl+C now if you do not wish to proceed... Sleeping for 5 seconds...

IP:     104.197.248.92, port 5985
Host:		104.197.248.92
Hostname:	92.248.197.104.bc.googleusercontent.com
Title:		Not Found
Server:		Microsoft-HTTPAPI/2.0
Location:	/
Certs:

IP:		  99.198.135.224, port 7547
Host:		99.198.135.224
Hostname:	99-198-135-224.mci.googlefiber.net
Title:		404: Not Found
Server:		TornadoServer/2.3
Location:	/
Certs:


-> % ruby shocens.rb -q "shodan"
[+] Beginning Censys search for shodan

[+] 127 results for shodan
[!] This could take over 7 minutes... Ctrl+C now if you do not wish to proceed... Sleeping for 5 seconds...

[+] Parsing page 1 of 2

Host:		    104.236.198.48: ports 443, 80, 25
Server:		  nginx/1.4.6 (Ubuntu)
Powered By:	Express
Title:		  Shodan Blog
Cert Names:	*.shodan.io, *.shodan.io, shodan.io
```

* CSV of data
* Text file of IPs found
* Text file of parsed websites 
* Text file of IPs, ports for diffing

#### Features
* Shodan query by for IP address/CIDR or org name
* Censys query for all ipv4 query terms
* Supports searching multiple queries by newline separated file
* Diffs last scan run (file format of ip, port) so you can watch for changes over time

Designed for targeted recon and smaller search scopes. Results over several thousand begin to get a bit unweildy.

You can get some data from ARIN via registered netblocks, but that's only part of the picture.
Many orgs today using cloud services and of course those IPs aren't going to be registered to your target org. And when AWS can tie
directly into a datacenter, these servers become quite valuable. If a dev stands up a service with HTTPS using a corporate certificate
it's likely going to be picked up and indexed by shodan or censys, so we can make use of that.

Lots of potential to pull additional data from both Censys and Shodan and cross query to fill in the blanks. Pull requests welcomed.

Shodan - https://www.shodan.io/
  * TODO: highlight the search options

Censys.io - https://censys.io/
  * TODO : highlight the search options

Note, both Censys and Shodan have fairly solid and libraries which are worth taking a look at as well.
* https://github.com/Censys/censys-python
* https://github.com/achillean/shodan-python
* https://cli.shodan.io/

