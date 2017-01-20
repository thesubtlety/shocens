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

require 'shodan'
require 'optparse'
require 'time'
require 'ruby_dig' #no-op with ruby 2.3+

def write_to_file(output_file, data)
	File.open(output_file, "a") do |f|
		# fragile:( assuming only arrays are being passed in
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
	uniq_websites = $websites.uniq
	uniq_ips = $ips.uniq

	puts "\n"
	if !uniq_websites.empty?; write_to_file($websites_file,uniq_websites);  puts "[+] Saved #{$websites_file}" end
	if !uniq_ips.empty?; write_to_file($ip_list_file, uniq_ips); puts "[+] Saved #{$ip_list_file}" end

  if !$verbose_host_info.empty?
    csv_header = "ip,port,host,http_host,title,server,location,certs"
	  write_to_file($csv_out_file,[csv_header])
	  write_to_file($csv_out_file, $verbose_host_info)
    puts "[+] Saved #{$csv_out_file}"
  end
	
	File.open($ips_ports_list_file, 'w') do |f|
		$current_results_hash.sort{|k,v| k[1]<=>v[1]}.each do |k,v| 
			f.puts "#{k}, #{v.join(", ")}"
		end
		puts "[+] Saved #{$ips_ports_list_file}"
	end
end

def parse_results(res)
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
			$websites << tmpwebsites if !tmpwebsites.empty? 
			tmpwebsites2 = extcerts.split(/[,|]/)
			$websites << tmpwebsites2  if !tmpwebsites2.empty?

		rescue Exception => e
			puts "\t\tError: #{e.to_s}"
			puts "\t\tError: #{e.backtrace}"
		end 
	end
end

def search(query)
	c = 1
	query.each do |q|
		begin
			if c % 9 == 0 then sleep 10 end
			
			pagenum = 1
			res = @api.search(q, :page => pagenum)
			total_pages = (res['total'] / 100) + 1

			puts "\nSearching #{res['total']} results in #{q}" 
			parse_results(res)
			
			d = 1
			until pagenum >= total_pages
				if d % 9 == 0 then sleep 10 end
				pagenum += 1
				res = @api.search(q, :page => pagenum)
				parse_results(res)	
				d += 1
			end

			c += 1
		rescue Exception => e
			puts "Error: #{e.to_s}"
			next
		end

	end
end

def main
	start = Time.now

	$help = ""
	options = {}
	
	#options setup. this is ugly, TODO
	$by_org_name =  nil
	$range_file = nil
	$save_output = nil
	$diff_last_scan = nil
	OptionParser.new do |opt|
		opt.on("-o", "--by-org=ORG_NAME", "Search by organization name") { |o| $by_org_name = o }
		opt.on("-f", "--by-ips=FILE", "Search by IPs in CIDR format. File must be newline separated.") { |o| $range_file = o }
		opt.on("-s", "--save-output", "Write output to csv file, ip list file, diff file") { |o| $save_output = TRUE}
		opt.on("-d", "--diff-last", "Compare last scan results and update diff file") { |o| $diff_last_scan = TRUE}
		opt.on_tail("-h", "--help", "Show this message") { puts opt; exit }
		$help = opt
	end.parse!
	if $range_file.nil? and $by_org_name.nil?
		# TODO needs better error handling
		# check file exists here, query is okay, no nuls etc
		puts $help 
		exit 1
	end

	query = [] 
	case
	when $by_org_name
		query << "org:\"#{$by_org_name}\""
		puts "\n[+] Beginning search for #{$by_org_name}"
		search(query)
	when $range_file
		# TODO strip empty strings
		if File.exist?($range_file)
			File.foreach($range_file) do |l|
				next if l.strip.empty?
				query << "net:" + l.strip
			end
			else
				puts "[!] #{$range_file} doesn't exist! Exiting..."
				exit 1		
		end
		puts "\n[+] Beginning Shodan search..."
		search(query)
	else
		puts "[!] Error parsing query. Check your options..."
		puts $help
	end

	diff_last_scan if $diff_last_scan
	save_output if $save_output

	puts "\n[+] Found #{$ips.uniq.count} hosts..."
	puts "[+] Found #{$websites.uniq.count} websites in certificates..."

	finish = Time.now
	delta = finish - start
	puts "\n[+] Completed in about #{delta.to_i / 60} minutes"
end


# Globals are bad
time                  = Time.now.strftime("%Y%m%d%H%M")
$csv_out_file         = "shodan-verbose-output-#{time}.csv"
$diff_file            = "shodan-new-results-#{time}.txt"
$ip_list_file         = "shodan-ips-list-#{time}.txt"
$websites_file        = "shodan-certwebsites-output-#{time}.txt"
$ips_ports_list_file  = "shodan-ips-ports-list.txt"
$current_results_hash = {}
$verbose_host_info    = []
$websites             = []
$ips                  = []

$shodan_key = ENV["SHODAN_KEY"] || raise("[!] Missing SHODAN_KEY environment variable...")
@api = Shodan::Shodan.new($shodan_key)

main

