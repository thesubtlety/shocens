require 'rest-client'
require 'json'
require 'base64'
require 'optparse'

CENSYS_API_URL = "https://www.censys.io/api/v1"
CENSYS_UID = ENV["CENSYS_UID"]
CENSYS_SECRET = ENV["CENSYS_SECRET"]
$censys_range_file = nil
$help = ""

$ips = []
$ips_and_ports = []
$verbose_host_info = []
$verbose_host_info_csv = []
$cert_sites = []
$token_bucket = 0
$censys_query = ""

#
#120 request/minute (no slow needed for one page @101 results per query)
#if more than one page. naiive is sleep for five minutes, fill up bucket again
def check_token_bucket
    if $token_bucket >= 115
      puts "[!] Sleeping for five to prevent lock out...\n"
      sleep 60*5
      $token_bucket = 0
    end
end

def catch_query_error(e,tries)
    puts "\n[-] Error: #{e.to_s}"
    puts "#{e.backtrace.join("\n")}"
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


def parse_censys_results(results)
  results["results"].each do |e| 
    ip = e["ip"] 
    ports = e["protocols"].map do |e| e.split("/")[0] end

    $ips << ip
    $ips_and_ports << [ip + ", " + ports.join(", ").to_s]

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
      $verbose_host_info_csv << host_info

    rescue Exception => e
      puts "\n[-] Error: #{e.to_s}"
      puts "#{e.backtrace}"
      next   
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
          puts "\n[+] Searching #{count} results for #{returned_query}\n"
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

#TODO cert parsing
#pass use certificate instead of ipv4 query /search/certificates instead of /search/ipv4
#({:query => "domain.com",:fields=>["parsed.subject_dn","parsed.issuer_dn","parsed.fingerprint_sha256"]})
#RestClient.get "#{CENSYS_API_URL}/view/certificates/sha256hashhere",{:Authorization => "Basic #{Base64.strict_encode64(CENSYS_UID+":"+CENSYS_SECRET)}"}
#r['results'].first['parsed.subject_dn'][0].split("CN=")[1]
#c['parsed']['names']
#c['parsed']['subject_dn']

options = {}
OptionParser.new do |opt|
  opt.banner = "Usage: censys.rb [options]"
  opt.on("-f", "--file=FILE", "List of search terms separated by newline") { |o| $censys_range_file = o }
#  opt.on("-c", "--certificates", "Search Censys.io certificate data instead of ipv4 domain") { |o| $certificate = o } #
  opt.on("-q", "--query=QUERY", 'Your censys.io query. Examples: \'127.0.0.1\' or \'domain.tld\'
                                        or \'parsed.extensions=="domain.tld"\' or \'autonomous_system.description:"target"\'
                                        See https://censys.io/overview#Examples') { |q| $censys_query = q }
  opt.on_tail("-h", "--help", "Show this message") { puts opt; exit }
  $help = opt
end.parse!

start = Time.now

query = []
case
when $censys_query
  query << "#{$censys_query}"
  puts "[+] Beginning search for #{$censys_query}"
  censys_search(query)
when $censys_range_file
  if File.exist?($censys_range_file)
    File.foreach($censys_range_file) do |l|
      next if l.strip.empty?
      query << l.strip
    end
    else
      puts "[!] #{$censys_range_file} doesn't exist! Exiting..."
      exit 1
  end
  puts "\n[+] Beginning Censys search..."
  censys_search(query)
else
  puts "[!] Error parsing query. Check your options..."
  puts $help
end

$censys_csv_file = "censys-out.csv"
$verbose_host_info_csvheader = "ip,ports,server,powered_by,title,link,cert_names"
File.open($censys_csv_file,"a") do |f|
  f.puts $verbose_host_info_csvheader
  f.puts $verbose_host_info_csv
end
$certsites_file="certsites.txt"
File.open($certsites_file,"a") do |f|
  f.puts $cert_sites.flatten.uniq.reject(&:nil?).reject(&:empty?).sort_by(&:downcase)
end

finish = Time.now

puts "\n[+] Finished in #{(finish-start).to_i / 60} minutes"
puts "[+] Parsed #{$ips.uniq.count} results"
puts "[+] Found #{$cert_sites.flatten.uniq.count} certificates"

