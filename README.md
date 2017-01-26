## Shocens

Query Shodan and Censys

#### Usage

* Install required gems                 `gem install shodan rest-client ruby_dig`
* Export your Shodan API key            => `export SHODAN_KEY="abcd123"`
* Export your Censys API id             => `export CENSYS_UID="abcd123"`
* Export your Censys API secret         => `export CENSYS_SECRET="abcd123"`

Note:

* To use Shodan filters, you must have a paid [membership](https://account.shodan.io/) or you will likely get 0 results.
It's only ~$45, frequently discounted, possibly free for .edu addresses, and totally worth it.
* [Censys.io](https://censys.io/) is free but requires registration.

#### Features
* Shodan query with filters
* Censys query for all supported ipv4 query terms
* Supports searching multiple queries by newline separated file
* Output results in CSV, TXT
* Diffs last scan run (just diffing a file [ip, ports]) so you can watch for changes over time

I have a bit more background written up over at https://www.thesubtlety.com/query-shodan-and-censys-with-shocens/

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
-> % ruby shocens.rb -s 'shodan' -t org -l 100
[+] Beginning Shodan search for org:google
[+] 687497 results in org:"google"
[+] Limiting results to 1 pages...

IP:		      104.155.22.29, port 443
Host:		104.155.22.29
Hostname:	29.22.155.104.bc.googleusercontent.com
Title:		Bundeswehr Wissensdatenbank - BW PEDIA
Server:		Apache/2.4.10 (Debian)
Location:	/
Certs:		www.bwpedia.de 


-> % ruby shocens.rb -q 'parsed.extensions="shodan"' -l 100
[+] Beginning Shodan search for org:google
[+] 687497 results in org:"google"
[+] Limiting results to 1 pages...

[+] Parsing page 1 of 1

Host:		104.131.0.69: ports 80
Server:		nginx/1.4.6 (Ubuntu)
Powered By:	
Title:		Shodan Internet Census
Cert Names:	, 

```
*Optional Output*

* CSV of data
* Text file of IPs found
* Text file of parsed websites 
* Text file of IPs, ports for diffing

It's worth noting that both Censys and Shodan have fairly solid and libraries which are worth taking a look at as well.

* https://github.com/Censys/censys-python
* https://github.com/achillean/shodan-python
* https://cli.shodan.io/

