module Racket
module L5
# Check Point Cluster Control Protocol (CCP)
#
# Based on (now out-of-date) Wireshark dissector:
# http://anonsvn.wireshark.org/wireshark/trunk/epan/dissectors/packet-cpha.c
class CCP < RacketPart
  # Magic Number
  unsigned :magic, 16, { :default => 0x1a90 } 
  # Protocol version
  unsigned :version, 16, { :default => 2000 }
  # Cluster number
  unsigned :cluster, 16
  # HA OpCode
  unsigned :opcode, 16
  # Source interface
  unsigned :if, 16
  # Random ID
  unsigned :random, 16
  # Source machine ID
  unsigned :smachine, 16
  # Destination machine ID
  unsigned :dmachine, 16
  # Policy ID
  unsigned :policy, 16
  # Filler
  unsigned :filler, 16
  # Payload
  rest :payload
end
end
end
