##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy.
#
# The following guys from ERP-SCAN deserve credit for their contributions -
# Alexandr Polyakov, Alexey Sintsov, Alexey Tyurin, Dmitry Chastukhin and
# Dmitry Evdokimov.
#
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis
# who have Beta tested the modules and provided excellent feedback. Some people
# just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'rubygems'
begin
  require 'nwrfc'
rescue LoadError
  abort("[x] This module requires the NW RFC SDK ruby wrapper (http://rubygems.org/gems/nwrfc) from Martin Ceronio.")
end

class Metasploit4 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include NWRFC

  def initialize
    super(
      'Name' => 'SAP RFC Client Enumerator',
      'Description' => %q{
          This module attempts to brute force the available SAP clients via the RFC interface.
          Default clients can be tested without needing to set a CLIENT.
          This module can execute through a SAP Router if SRHOST and SRPORT values are set.
          The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
          },
          'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
          'Author' => [ 'nmonkee' ],
          'License' => MSF_LICENSE
          )

  register_options(
       [
        OptString.new('CLIENT', [false, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
        OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
        OptString.new('SRPORT', [false, 'SAP Router Port Number', nil])
      ], self.class)
  end

  def run_host(ip)
    if datastore['CLIENT'].nil?
      print_status("Using default SAP client list")
      client = ['000','001','066']
    else
      client = []
        if datastore['CLIENT'] =~ /^\d{3},/
          client = datastore['CLIENT'].split(/,/)
          print_status("Brute forcing clients #{datastore['CLIENT']}")
        elsif datastore['CLIENT'] =~ /^\d{3}-\d{3}\z/
          array = datastore['CLIENT'].split(/-/)
          client = (array.at(0)..array.at(1)).to_a
          print_status("Brute forcing clients #{datastore['CLIENT']}")
        elsif datastore['CLIENT'] =~ /^\d{3}\z/
          client.push(datastore['CLIENT'])
          print_status("Brute forcing client #{datastore['CLIENT']}")
        else
          print_status("Invalid CLIENT - using default SAP client list instead")
          client = ['000','001','066']
        end
    end

    user = "mwrlabs"
    pass = "06071992"

    rport = datastore['rport'].to_s.split('')
    sysnr = rport[2]
    sysnr << rport[3]

    client.each { |client|
    	enum_client(user,client,pass,datastore['rhost'],datastore['rport'],sysnr)
    }
  end

  def enum_client(user, client, pass, rhost, rport, sysnr)
    vprint_status("#{rhost}:#{rport} [SAP] Trying client: '#{client}'")
    ashost = rhost
    ashost = "/H/#{datastore['SRHOST']}/H/#{rhost}" if datastore['SRHOST']
    begin
      auth_hash = {"user" => user, "passwd" => pass, "client" => client, "ashost" => ashost, "sysnr" => sysnr}
      conn = Connection.new(auth_hash)
      success = true
    rescue NWError => e
      case e.message.to_s
      when /not available in this system/
        vprint_error("#{rhost}:#{rport} [SAP] client #{client} does not exist")
      when /Logon not possible/
        vprint_error("#{rhost}:#{rport} [SAP] client #{client} does not exist")
      when /Connection refused/
        vprint_error("#{rhost}:#{rport} [SAP] client #{client} connection refused")
      else
	success = true
      end
    end
        
    if success
      print_good("#{rhost}:#{rport} [SAP] client found - #{client}")
      report_auth_info(
        :host => rhost,
        :sname => 'sap-gateway',
        :proto => 'tcp',
        :port => rport,
        :user => user,
        :pass => pass,
        :client => client,
        :sysnr => sysnr,
        :source_type => "user_supplied",
        :target_host => rhost,
        :target_port => rport
        )
      return
    end
  end
end
