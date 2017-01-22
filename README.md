Query Shodan and Censys. Shodan support for IP address or org name. Censys support for all ipv4 query terms. Supports multiple queries by newline separated file.

Lots of potential to pull additional data from both Censys and Shodan and cross query to fill in the blanks. Pull requests welcomed.

Currently pulling from ipv4 space. Designed for targeted searches and smaller search scopes. Results over several thousand begin to get a bit unweildy.

Originally intended for targeted recon. You can get some data from ARIN via registered netblocks, but that's only part of the picture.
Many orgs today using cloud services and of course those IPs aren't going to be registered to your target org. And when AWS can tie
directly into a datacenter, these servers become quite valuable. If a dev stands up a service with HTTPS using a corporate certificate
it's likely going to be picked up and indexed by shodan or censys, so we can make use of that.

Shodan - https://www.shodan.io/
  * TODO: highlight the search options

Censys.io - https://censys.io/
  * TODO : highlight the search options

#### Usage

* If querying Shodan
  * Requires `shodan` gem               => `gem install shodan`
  * Requires `ruby_dig` for ruby <2.3   => `gem install ruby_dig`
* Export your Shodan API key            => `export SHODAN_KEY="abcd123"`
* Export your Censys API id             => `export CENSYS_UID="abcd123"`
* Export your Censys API secret         => `export CENSYS_SECRET="abcd123"`

```
Usage: censys.rb [options]
    -o, --shodan-by-org=ORG_NAME     Search Shodan by organization name
    -i, --shodan-by-ips=FILE         Search by IPs in CIDR format separated by newline
                                        Example: 127.0.0.0/24. Note 0 in final octet.
    -c, --censys-by-file=FILE        Search Censys with list of search terms separated by newline
    -q, --censys-query=QUERY         Your censys.io query. Examples: '127.0.0.1' or 'domain.tld'
                                        or 'parsed.extensions=="domain.tld"'
                                        or 'autonomous_system.description:"target"'
                                        See https://censys.io/overview#Examples
    -s, --save-output                Write output to csv file, ip list file, diff file
    -d, --diff-last                  Compare last scan results and update diff file
    -h, --help                       Show this message
```

#### Output
* CSV of data
* Text file of IPs found
* Text file of parsed websites 

