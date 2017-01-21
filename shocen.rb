# Author: thesubtlety
# Query Shodan on multiple ranges of ip addresses or by org name
#
# Requires ruby_dig gem if you're using ruby <2.3... => `gem install ruby_dig`
# Export your Shodan API key to SHODAN_KEY           => `export SHODAN_key="abcd123"
#
# Usage: ruby shocen.rb [options]
#    -o, --by-org=ORG_NAME            Search by org name
#    -f, --by-ips=FILE                Search by IPs in CIDR format. Newline separated file
#    -s, --save-output                Write output to csv file
#    -d, --diff-last                  Diff last scan and save update file
#    -h, --help                       Show this message
#

# Shodan
require 'shodan'
require 'optparse'
require 'time'
require 'ruby_dig' #no-op with ruby 2.3+

# Censys
require 'rest-client'
require 'json'
require 'base64'
require 'optparse'

# Censys
#120 request/minute (no slow needed for one page @101 results per query)
#if more than one page. naiive is sleep for five minutes, fill up bucket again
def check_token_bucket
    if $token_bucket >= 115
      puts "[!] Sleeping for five to prevent lock out...\n"
      sleep 60*5
      $token_bucket = 0
    end
end

# Censys
def catch_query_error(e,tries)
    puts "\n[-] Error: #{e.to_s}"
    puts "#{e.backtrace.join("\n")}" if !e.response
    case e.response.code
    when 429
      puts "\n[-] Error: #{e.response}"
      puts "[!] Sleeping for 5 minutes to recharge... Please hold...\n\n"
      sleep 60*5
    when 400
      puts "\n[-] Error: #{e.response}"
      puts "[-] Check your query parameters..."
      exit 1
    else
      puts "\n[-] Error: #{e.response}"
      puts "[!] Sleeping a minute... maybe the problem will go away...\n\n"
      sleep 60
    end
end

def write_to_file(output_file, data)
	File.open(output_file, "a") do |f|
		# fragile assuming only arrays are being passed in
		f.puts "#{data.join("\n")}"
	end
end

def add_to_hash(ip,port)
	if $current_results_hash[ip]
		$current_results_hash[ip] << port
	else
		$current_results_hash[ip] = [port]
	end
end

def diff_last_scan
	old_results_array = []
	if File.exist?($ips_ports_list_file)
		File.foreach($ips_ports_list_file) do |l|
			old_results_array << [l.strip]
		end
	else
		puts "\n[!] No previous hosts to compare to..."
	end

	current_results_array = []
	$current_results_hash.sort{|k,v| k[1]<=>v[1]}.each do |k,v|
		current_results_array << ["#{k}, #{v.join(", ")}"]
	end

	diff = current_results_array - old_results_array
	if diff.empty?
		puts "\n[!] No new properties"
	else
		puts "\n[!] New properties in this scan"
		puts diff.join("\n")
		write_to_file($diff_file, diff)
		puts "[+] Saved #{$diff_file}"
	end
end

def save_output
	uniq_websites = $cert_sites.flatten.uniq.reject(&:nil?).reject(&:empty?).sort_by(&:downcase)
	uniq_ips = $ips.uniq.sort

  # write websites and ips
	puts "\n"
	if !uniq_websites.empty?; write_to_file($cert_sites_file,uniq_websites);  puts "[+] Saved #{$cert_sites_file}" end
	if !uniq_ips.empty?; write_to_file($ip_list_file, uniq_ips); puts "[+] Saved #{$ip_list_file}" end

  # write CSV
  if !$verbose_host_info.empty?
    header = ""
    ($shodan_org_name || $shodan_search_file) ? header=SHODAN_CSV_HEADER : header=CENSYS_CSV_HEADER
	  write_to_file($verbose_host_info_file,[header])
	  write_to_file($verbose_host_info_file, $verbose_host_info)
    puts "[+] Saved #{$verbose_host_info_file}"
  end

  # write ip/ports hash for diff list
	if !$current_results_hash.empty?
    File.open($ips_ports_list_file, 'w') do |f|
      $current_results_hash.sort{|k,v| k[1]<=>v[1]}.each do |k,v|
        f.puts "#{k}, #{v.join(", ")}"
      end
      puts "[+] Saved #{$ips_ports_list_file}"
    end
  end
end

def parse_censys_results(results)
  results["results"].each do |e|
    ip = e["ip"]
    ports = e["protocols"].map do |e| e.split("/")[0] end

    $ips << ip
    add_to_hash(ip,ports)

    puts "\nHost:\t\t#{ip}: ports #{ports.join(", ")}"

    tries ||= 0
    check_token_bucket
    begin
      detailed_resp = RestClient.get "#{CENSYS_API_URL}/view/ipv4/#{ip}",
                    {:Authorization => "Basic #{Base64.strict_encode64("#{CENSYS_UID}:#{CENSYS_SECRET}")}"}
      $token_bucket += 1
    rescue Exception => e
      catch_query_error(e,tries)
      ((tries += 1)) <3 ? retry : exit(1)
    end

    details = JSON.parse(detailed_resp)
    begin
      server = details.fetch("80",{}).fetch("http",{}).fetch("get",{}).fetch("headers",{}).fetch("server","")
      powered_by = details.fetch("80",{}).fetch("http",{}).fetch("get",{}).fetch("headers",{}).fetch("x_powered_by","")
      title = details.fetch("80",{}).fetch("http",{}).fetch("get",{}).fetch("title","").split("\n")[0] || ""
      other_names = []
      other_names << [details.fetch("443",{}).fetch("https",{}).fetch("tls",{}).fetch("certificate",{}).fetch("parsed",{}).fetch("subject_dn","").split("CN=")[1]]
      other_names << details.fetch("443",{}).fetch("https",{}).fetch("tls",{}).fetch("certificate",{}).fetch("parsed",{}).fetch("extensions",{}).fetch("subject_alt_name",{}).fetch("dns_names","")
      uniq_cert_names_csv = other_names.uniq.join("|")

      puts "Server:\t\t#{server}"
      puts "Powered By:\t#{powered_by}"
      puts "Title:\t\t#{title}"
      puts "Cert Names:\t#{other_names.uniq.join(", ")}"

      $cert_sites.concat(other_names.uniq)

      link = "https://censys.io/ipv4/#{ip}"
      host_info = "#{ip},#{ports.join("|")},#{server},#{powered_by},#{title},#{link},#{uniq_cert_names_csv}"
      $verbose_host_info << host_info

    rescue Exception => e
      puts "\n[-] Error: #{e.to_s}"
      puts "#{e.backtrace}"
      next
    end
  end
end

def parse_shodan_results(res)
	res["matches"].each do |h|
		begin
			ip = h["ip_str"].to_s || "0"
			port = h["port"].to_s || "0"
			add_to_hash(ip,port)
			host = h.dig("hostnames").join(",") || ""
			http_host = h.dig("http","host") || ""
			title = h.dig("http","title") || ""
			server = h.dig("http","server") || ""
			location = h.dig("http","location") || ""
			subject_certs = h.dig("ssl","cert","subject","CN") || ""
			tmpextcerts = h.dig("ssl","cert","extensions", 0, "data") || ""
			# wow cert data is a mess
			extcerts = if !tmpextcerts.empty? then tmpextcerts.split(/\\x../).reject(&:empty?).drop(1).join(",") else "" end
			subject_certs = subject_certs.gsub(/[ \\()$%\!"#'\r\n]/,"")
			extcerts  = extcerts.gsub(/[ \\()$%\!"#'\r\n]/,"")

			puts "\n"
			puts "IP:\t\t" + ip.to_s + ", port " + port.to_s
			puts "Host:\t\t#{http_host}"
			puts "Hostname:\t#{host}"
			puts "Title:\t\t#{title.gsub(/[\t\r\n,]/,"")}"
			puts "Server:\t\t#{server}"
			puts "Location:\t#{location}"
			puts "Certs:\t\t#{subject_certs} #{extcerts}"
			puts "\n"

			host_info = "#{ip},#{port},#{host},#{http_host},#{title.gsub(/[\t\r\n,]/,"")},#{server},#{location},#{subject_certs.gsub!(",","|")} #{extcerts.gsub!(",","|")}"
			$verbose_host_info << host_info
			$ips << "#{ip}"

			tmpwebsites = subject_certs.split(/[,|]/)
			$cert_sites << tmpwebsites if !tmpwebsites.empty?
			tmpwebsites2 = extcerts.split(/[,|]/)
			$cert_sites << tmpwebsites2  if !tmpwebsites2.empty?

		rescue Exception => e
			puts "\t\tError: #{e.to_s}"
			puts "\t\tError: #{e.backtrace}"
		end
	end
end

def censys_search(query)
  query.each do |q|

    tries ||= 0
    begin
      pagenum = 1
      total_pages = 1
      until pagenum > total_pages
        check_token_bucket
        begin
          res = RestClient.post "#{CENSYS_API_URL}/search/ipv4", ({:query => q,:page => pagenum}).to_json,
                          {:Authorization => "Basic #{Base64.strict_encode64(CENSYS_UID+":"+CENSYS_SECRET)}"}
          $token_bucket += 1
        rescue Exception => e
          catch_query_error(e,tries)
          ((tries += 1)) <3 ? retry : exit(1)
        end
        results = JSON.parse(res)

        count = results["metadata"]["count"] || 0
        total_pages = results["metadata"]["pages"] || 0
        returned_query = results["metadata"]["query"] || ""

        if pagenum == 1
          puts "\n[+] Parsing #{count} results for #{returned_query}\n"
          if total_pages > 1
            puts "[!] #{count} results. This could take over #{((count/100) + ((count / 115) * 5))} minutes... Ctrl+C now if you do not wish to proceed... Sleeping for 5 seconds..."
            sleep 7
          end
        end

        puts "\n[+] Parsing page #{pagenum} of #{total_pages}\n"
        parse_censys_results(results)
        pagenum += 1
      end

    rescue SystemExit, Interrupt
      puts "\n[!] Ctrl+C caught. Exiting. Goodbye..."
    rescue Exception => e
      puts "\n[-] Error: #{e.to_s}"
      puts "#{e.backtrace}"
    end
  end
end

#TODO robustify like censys
def search_shodan(query)
	c = 1
	query.each do |q|
		begin
			if c % 9 == 0 then sleep 10 end

			pagenum = 1
			res = @api.search(q, :page => pagenum)
			total_pages = (res['total'] / 100) + 1

			puts "\nParsing #{res['total']} results in #{q}"
			parse_shodan_results(res)

			d = 1
			until pagenum >= total_pages
				if d % 9 == 0 then sleep 10 end
				pagenum += 1
        puts "\n[+] Parsing page #{pagenum} of #{total_pages}\n"
				res = @api.search(q, :page => pagenum)
				parse_shodan_results(res)
				d += 1
			end

			c += 1
		rescue Exception => e
			puts "Error: #{e.to_s}"
			next
		end

	end
end

#TODO censys cert parsing
#pass use certificate instead of ipv4 query /search/certificates instead of /search/ipv4
#({:query => "domain.com",:fields=>["parsed.subject_dn","parsed.issuer_dn","parsed.fingerprint_sha256"]})
#RestClient.get "#{CENSYS_API_URL}/view/certificates/sha256hashhere",{:Authorization => "Basic #{Base64.strict_encode64(CENSYS_UID+":"+CENSYS_SECRET)}"}
#r['results'].first['parsed.subject_dn'][0].split("CN=")[1]
#c['parsed']['names']
#c['parsed']['subject_dn']

def main
	start = Time.now

	$help = ""
	options = {}

	#TODO options setup. this is ugly.
	$shodan_org_name =  nil
	$shodan_search_file = nil
	$censys_search_file = nil
  $censys_query = nil
	$save_output = nil
	$diff_last_scan = nil
	OptionParser.new do |opt|
    opt.banner = "Usage: censys.rb [options]"
		opt.on("-o", "--shodan-by-org=ORG_NAME", "Search Shodan by organization name") { |o| $shodan_org_name = o }
		opt.on("-i", "--shodan-by-ips=FILE", "Search by IPs in CIDR format separated by newline
                                        Example: 127.0.0.0/24. Note 0 in final octet.") { |o| $shodan_search_file = o }

    opt.on("-c", "--censys-by-file=FILE", "Search Censys with list of search terms separated by newline") { |o| $censys_search_file = o }
    opt.on("-q", "--censys-query=QUERY", 'Your censys.io query. Examples: \'127.0.0.1\' or \'domain.tld\'
                                        or \'parsed.extensions=="domain.tld"\'
                                        or \'autonomous_system.description:"target"\'
                                        See https://censys.io/overview#Examples') { |q| $censys_query = q }

		opt.on("-s", "--save-output", "Write output to csv file, ip list file, diff file") { |o| $save_output = TRUE}
		opt.on("-d", "--diff-last", "Compare last scan results and update diff file") { |o| $diff_last_scan = TRUE}

		opt.on_tail("-h", "--help", "Show this message") { puts opt; exit }
		$help = opt
	end.parse!
	if FALSE
    # TODO needs error handling
		# check file exists here, query is okay, no nuls etc
		puts $help
		exit 1
	end

	query = []
	case
    when $shodan_org_name
      puts "\n[+] Beginning Shodan search for #{$shodan_org_name}"
      query << "org:\"#{$shodan_org_name}\""
      search_shodan(query)

    when $shodan_search_file
      # TODO strip empty strings
      if File.exist?($shodan_search_file)
        File.foreach($shodan_search_file) do |l|
          next if l.strip.empty?
          query << "net:" + l.strip
        end
        else
          puts "[!] #{$shodan_search_file} doesn't exist! Exiting..."
          exit 1
      end
      puts "[+] Beginning Shodan search..."
      search_shodan(query)

    when $censys_query
      query << "#{$censys_query}"
      puts "[+] Beginning search for #{$censys_query}"
      censys_search(query)

    when $censys_search_file
      if File.exist?($censys_search_file)
        File.foreach($censys_search_file) do |l|
          next if l.strip.empty?
          query << l.strip
        end
        else
          puts "[!] #{$censys_search_file} doesn't exist! Exiting..."
          exit 1
      end
      puts "\n[+] Beginning Censys search..."
      censys_search(query)

    else
      puts "[!] Error parsing query. Check your options..."
      puts $help
	end

	diff_last_scan if $diff_last_scan
	save_output if $save_output

	puts "\n[+] Found #{$ips.uniq.count} hosts..."
	puts "[+] Found #{$cert_sites.uniq.count} websites in certificates..."

	finish = Time.now
	delta = finish - start
	puts "\n[+] Completed in about #{delta.to_i / 60} minutes"
end

#TODO differentiate output censys vs shodan?
# Globals are bad
time                  = Time.now.strftime("%Y%m%d%H%M")
$verbose_host_info_file = "verbose-output-#{time}.csv"
$diff_file            = "new-results-#{time}.txt"
$ip_list_file         = "ips-list-#{time}.txt"
$cert_sites_file      = "certwebsites-output-#{time}.txt"
$ips_ports_list_file  = "ips-ports-list.txt"
$current_results_hash = {}
$verbose_host_info    = []
$cert_sites           = []
$ips                  = []
$token_bucket         = 0
CENSYS_CSV_HEADER     = "ip,ports,server,powered_by,title,link,uniq_cert_names_csv"
SHODAN_CSV_HEADER     = "ip,port,host,http_host,title,server,location,certs"

CENSYS_API_URL = "https://www.censys.io/api/v1"
CENSYS_UID = ENV["CENSYS_UID"] || raise("[!] Missing CENSYS_UID environment variable...")
CENSYS_SECRET = ENV["CENSYS_SECRET"] || raise("[!] Missing CENSYS_SECRET environment variable...")

SHODAN_KEY = ENV["SHODAN_KEY"] || raise("[!] Missing SHODAN_KEY environment variable...")
@api = Shodan::Shodan.new(SHODAN_KEY)

main

