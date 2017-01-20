Query Shodan and Censys on multiple ranges of ip addresses or by org name

Currently supporting Shodan. Censys.io data query is a work in progress.

* Requires `ruby_dig` gem if you're using ruby <2.3. => `gem install ruby_dig`
* Export your Shodan API key to SHODAN_KEY           => `export SHODAN_key="abcd123"`

```
Usage: ruby shocen.rb [options]
    -o, --by-org=ORG_NAME            Search by organization name
    -f, --by-ips=FILE                Search by IPs in CIDR format. File must be newline separated.
    -s, --save-output                Write output to csv file, ip list file, diff file
    -d, --diff-last                  Compare last scan results and update diff file
    -h, --help                       Show this message
```
