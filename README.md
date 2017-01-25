## Shocens

Query Shodan and Censys 

#### Usage

* Install required gems                 `gem install shodan rest-client ruby_dig`
* Export your Shodan API key            => `export SHODAN_KEY="abcd123"`
* Export your Censys API id             => `export CENSYS_UID="abcd123"`
* Export your Censys API secret         => `export CENSYS_SECRET="abcd123"`

```
Usage: ruby shocens.rb [options]
    -s, --shodan-search=SEARCH_TERM  Search Shodan by search term
    -f, --shodan-by-file=FILE        Search terms separated by newline
    -t, --shodan-filter=FILTER       Restrict Shodan search to standard filters
                                        Examples: -t org -s 'org name' queries 'org:"org name"'
                                        or -t net -s "192.168.1.0/24" queries "net:192.168.1.0/24"
    -q, --censys-search=SEARCH_TERM  Your censys.io query. Examples: '127.0.0.1' or 'domain.tld'
                                        or 'parsed.extensions=="domain.tld"'
                                        or 'autonomous_system.description:"target"'
                                        See https://censys.io/overview#Examples
    -F, --censys-by-file=FILE        Search Censys with list of search terms separated by newline
    -o, --save-output                Write output to csv file, ip list file, diff file
    -l, --limit=NUM                  Limit result set to NUM multiple of 100
    -d, --diff-last                  Compare last scan results and update diff file
    -h, --help                       Show this message
```

#### Output

```bash
-> % ruby shocens.rb -q 'parsed.extensions="shodan"' -l 100
[+] Beginning Shodan search for org:google
[+] 687497 results in org:"google"
[+] Limiting results to 1 pages...

IP:		  104.155.22.29, port 443
Host:		104.155.22.29
Hostname:	29.22.155.104.bc.googleusercontent.com
Title:		Bundeswehr Wissensdatenbank - BW PEDIA
Server:		Apache/2.4.10 (Debian)
Location:	/
Certs:		www.bwpedia.de 


-> % ruby shocens.rb -q "shodan"
[+] Beginning Censys search for parsed.extensions="shodan"
[+] 133 results for parsed.extensions="shodan"
[+] Limiting results to 1 pages...

[+] Parsing page 1 of 1

Host:		104.131.0.69: ports 80
Server:		nginx/1.4.6 (Ubuntu)
Powered By:	
Title:		Shodan Internet Census
Cert Names:	, 

```
Optional

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

