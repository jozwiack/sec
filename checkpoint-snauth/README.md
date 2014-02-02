Product Information
-------------------

Check Point Session Authentication agent is a service that is installed on
endpoint system in order to communicate with security gateway and allow it to
request and obtain user's credentials. Session Authentication is a part of
Legacy Authentication suite which provides different authentication methods to
allow or deny access to network resources.

R76 Security Gateway Technical Administration Guide[1][1] defines typical Session
Authentication operation in the following way:

  1. The user initiates a connection directly to the server
  2. The Security Gateway intercepts the connection
  3. The Session Authentication agent challenges the user for authentication
     data and returns this information to the gateway
  4. If the authentication is successful, the Security Gateway allows the
     connection to pass through the gateway and continue to the target server


Issue description
-----------------

Check Point Session Authentication agent version 4.1 and higher contains a flaw
which is caused by lack of peer authentication in SSL communication. Encrypted
communication between agent and security gateway has been introduced due to
several issues (e.g. [2][2], [3][3]) which were revealed in the previous versions
(4.0 and lower) of the product. Research showed that it is still possible to
exploit previously known vulnerabilities - gateway impersonation and credential
stealing - even though communication between agent and security gateway is
utilizing SSL. 

Communication between Session Authentication agent and security gateway is
performed using proprietary protocol. Since version 4.1 this communication
scheme uses SSL as an underlying protocol to enable encryption of both protocol
commands and user provided data. When SSL communication is negotiated between
gateway and agent following cipher suites are visible in SSL Client Hello
message as supported by Session Authentication agent:

    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
    TLS_DH_anon_WITH_RC4_128_MD5
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    TLS_DH_anon_WITH_DES_CBC_SHA
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA

RFC2246 refers to listed cipher suites:

    "The following cipher suites are used for completely anonymous
    Diffie-Hellman communications in which neither party is
    authenticated. Note that this mode is vulnerable to man-in-the-middle
    attacks and is therefore deprecated."

Taking into account above information it's possible to connect to Session
Authentication agent from attacker's machine, initiate SSL-based communication,
pass SSL handshake without being authenticated and use encrypted channel to
control agent (e.g. prompt user for login and password).

For attack to be successful attacker's machine must be allowed to connect to
machine on which agent is running. Newer versions of Session Authentication
agent include option to define three IP addresses which are allowed to issue
authentication requests to agent. When this option is used it limits possibility
of exploitation. Agent software has also "Allow any IP" option - when enabled
attacker doesn't need to take additional measures in order to be able to connect
to agent.


Proof of Concept
----------------

Attached PoC script simulates security gateway and allows credential stealing to
be performed over encrypted communication channel against Session Authentication
agent version 4.1 or higher.


Affected versions 
-----------------

Check Point Session Authentication agent, version 4.1 and higher


Vendor response 
---------------

Vendor has been informed about the issue on 8/8/2013. On 14/8/2013 vendor
informed about expected fix date: 15/10/2013. On 28/10/2013 vendor informed that
due to small user base and introduction of the Identity Awareness Software
Blade[4][4] legacy session authentication will be deprecated in the major release
of 2014.

Additionally vendor published SecureKnowledge article[5][5].


Credits
-------

It should be noted that this finding is partially based on work of
individuals who reported issues in the previous versions of Session
Authentication agent as referenced in [2][2] and [3][3].


References
----------


[1: R76 Security Gateway Technical Administration Guide](https://sc1.checkpoint.com/documents/R76/CP_R76_SGW_WebAdmin/6721.htm)
[1]: https://sc1.checkpoint.com/documents/R76/CP_R76_SGW_WebAdmin/6721.htm "R76 Security Gateway Technical Administration Guide"

[2: Check Point Firewall-1 Session Agent Impersonation Vulnerability](http://www.securityfocus.com/bid/1661/info)
[2]: http://www.securityfocus.com/bid/1661/info "Check Point Firewall-1 Session Agent Impersonation Vulnerability"

[3: Check Point Firewall-1 Session Agent Cleartext Authentication Credentials Spoofing Weakness](http://osvdb.org/show/osvdb/84985)
[3]: http://osvdb.org/show/osvdb/84985 "Check Point Firewall-1 Session Agent Cleartext Authentication Credentials Spoofing Weakness"

[4: Check Point Identity Awareness Software Blade](https://www.checkpoint.com/products/identity-awareness-software-blade/)
[4]: https://www.checkpoint.com/products/identity-awareness-software-blade/ "Check Point Identity Awareness Software Blade"

[5: Check Point sk98263](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk98263)
[5]:https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk98263 "Check Point sk98263"

<!---
vim: set textwidth=80 wrapmargin=2:
-->
