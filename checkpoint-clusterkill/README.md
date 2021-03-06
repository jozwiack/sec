Issue description
-----------------

Issue occurs when specially crafted CCP packets are send to all Check Point
ClusterXL cluster members. This causes clustered gateway to be confused about
state of its peer(s) which can lead to situation when all cluster members end
up in Ready/Standby state. Such case leads to denial of service where none
cluster member will forward network traffic.

For attack to be successful attacker must be able to sniff CCP traffic which
requires him/her to have direct access to broadcast domain in which "Sync" or
"Cluster + Sync" interfaces are located. In many cases this requirement may
considerably limit attack surface.

Issue concerns following ClusterXL modes:

  * New High Availability
  * Load Sharing (Unicast)
  * Load Sharing (Multicast)


Product information
-------------------

Issue affects operation of ClusterXL clusters utilizing CCP as underlying
protocol.

"ClusterXL Administration Guide R75" defines ClusterXL and CCP in the
following way:

(page 8)
"A ClusterXL cluster is a group of identical Check Point Security Gateways
connected in such a way that if one fails, another immediately takes its
place.  ClusterXL is a software-based Load Sharing and High Availability
solution that distributes network traffic between clusters of redundant
Security Gateways and provides transparent failover between machines in a
cluster."

(page 9)
"The Cluster Control Protocol (CCP) is the glue that links together the
machines in the Check Point Gateway Cluster. CCP traffic is distinct from
ordinary network traffic and can be viewed using any network sniffer."


Technical details
-----------------

High level description of the attack can be summarized in the following steps:

  1. Sniff for all CCP packets generated by cluster members
  2. From all sniffed packets select only "CCP Report source machine's state"
     packets (opcode = 1)
  3. For each selected packet set all payload bytes to 0
  4. Send back packet to wire leaving all other fields untouched

Ad 1. CCP runs over UDP and utilizes port 8116 for both source and
destination. Note that in most configurations CCP packets are send also on
interfaces which are not set as "Sync".

Ad 4. Especially following fields should match those from original frame:
  * CCP header fields
  * Source MAC should match following pattern:
    00:00:00:00:magic_number:member_id, where magic_number in default
    configuration equals 0xfe, member_id can be random
  * Destination MAC in multicast mode should match 01:00:05:xx:yy:zz where
    xx:yy:zz reflect last 3 octets of cluster virtual IP

Attached PoC consists of two files:

  * `ccp-kill.rb` - actual PoC code. It takes only one argument - interface
    name on which it will sniff and send CCP packets. It has been tested on
    BackTrack 5R3 with Ruby 1.8 and requires following Ruby gems: Racket,
    Pcaprub
  * `ccp.rb` - extension file for Racket describing CCP protocol fields (based
    on Wireshark CCP dissector). It needs to be placed in `lib/racket/l5` dir
    where Racket gem is installed

Running PoC on network where cluster "Sync" or "Cluster + Sync" interfaces are
located will cause cluster members transitioning from Active/Standby or
Active/Active states to Ready/Ready (Load Sharing) or Ready/Standby (New High
Availability). In this scenario none of cluster members will handle network
traffic utilizing cluster virtual IP address as a gateway.


Affected versions
-----------------

So far tests have been performed on SPLAT-based R75 Check Point gateway
installation reporting following version: R75 - Build 254 and CCP packets
reporting following version: 2000.

My (uneducated) guess is that at least other versions from R75 line would
behave in presented manner.


Vendor response
---------------

Vendor has been informed about the issue and came back with following
response:

"Check Point Cluster Control protocol is assumed to be sent over a trusted
network. Customer may achieve this by using a dedicated physical network
segment or by using VLANs. It is the responsibility of the customer to ensure
that the network is trusted."

Additionally vendor confirmed that in future releases packet digital
signatures for CCP will be introduced.


Workaround/solution
-------------------

Vendor response as well as already mentioned "ClusterXL Administration Guide
R75" (page 11) give hints about proper network design that will minimize
attack surface. Especially running "Cluster + Sync" interfaces which usually
mix both sync and 'normal' network traffic should be avoided.


References
----------

[Original Full Disclosure report](http://seclists.org/fulldisclosure/2013/Sep/40)

[Check Point response - SK94849](http://supportcontent.checkpoint.com/solutions?id=sk94849)

[Demo of PoC operation](http://youtu.be/pcg4oGXreKM)

