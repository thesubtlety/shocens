Query Shodan and Censys on multiple ranges of ip addresses or by org name

Currently supporting Shodan. Censys.io data query is a work in progress.

* Requires ruby_dig gem if you're using ruby <2.3... => `gem install ruby_dig`
* Export your Shodan API key to SHODAN_KEY           => `export SHODAN_key="abcd123"

```
Usage: ruby shocen.rb [options]
   -o, --by-org=ORG_NAME            Search by org name
   -f, --by-ips=FILE                Search by IPs in CIDR format. Newline separated file
   -s, --save-output                Write output to csv file
   -d, --diff-last                  Diff last scan and save update file
   -h, --help                       Show this message
```
