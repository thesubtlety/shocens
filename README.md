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

* Requires `ruby_dig` gem if you're using ruby <2.3  => `gem install ruby_dig`
* Export your Shodan API key            => `export SHODAN_KEY="abcd123"`
* Export your Censys API id             => `export CENSYS_UID="abcd123"`
* Export your Censys API secret         => `export CENSYS_SECRET="abcd123"`

```
Usage: ruby shocen.rb [options]
   -o, --by-org=ORG_NAME            Search by org name
   -f, --by-ips=FILE                Search by IPs in CIDR format. Newline separated file
   -s, --save-output                Write output to csv file
   -d, --diff-last                  Diff last scan and save update file
   -h, --help                       Show this message
```

#### Output
* CSV for sorting
* Text file for IPs found for easy import into nmap
* Text file for parsed websites 

