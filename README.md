# SSL/TLS protocol and cipher suite scanner with JSON output #
    -- noah@hack.se, 2013

Sslprobe does rudimentary SSL/TLS handshakes, from ClientHello up until
ServerHello Done and extracts a list of supported ciphers, certificates
and features such as session ID assignment and common TLS extensions.

A report is printed on stdout in JSON (it's not ASN.1, but it's simple!),
suitable for later inspection/processing.
Various protocol details are sent to stderr/syslog (filter with: `2>/dev/null`).

The certificates and the trust chain are not inspected at this time, even
though it would be interesting to to extract features such as subjectAltName,
expiry dates and bits.
The JSON output however includes an array of each of the server's presented
certificates, encoded in PEM-format (i.e, chunked base64 representation of
the DER), which is suitable for offline evaluation.

Usage
----
    $ ./sslprobe
    Usage: ./sslprobe <host> [port (= 443)] [output file]

Sslprobe assumes that the server speaks SSL/TLS natively on the choosen
TCP port, i.e, what many protocols such as HTTPS (443), POP3S (995),
IMAPS (993) or IRCS (6697) do.

Some protocols, notably SMTP, FTP and IMAP, allow SSL/TLS to be negotiated
using STARTTLS (see for instance [RFC3207](http://tools.ietf.org/html/rfc3207)).

Sslprobe supports STARTTLS on SMTP if the port argument is set to 25.  No other
STARTTLS protocols are supported at the moment.  It's however quite easy to
implement support for new protocols (see `smtp.c` and `proto.c` for an example).

Related work
----
* <https://www.ssllabs.com> provides an extensive test of HTTPS sites online
* <https://github.com/iSECPartners/sslyze> contains one of the tools behind SSL Labs
* [EFF.org SSL Observatory](https://www.eff.org/observatory) documents and investigates certificate use on the public internet

Useful RFCs
---
* [SSLv2](http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html) SSL 0.2 Protocol specification
* [RFC6101](http://tools.ietf.org/html/rfc6101) The Secure Sockets Layer (SSL) Protocol Version 3.0
* [RFC5246](http://tools.ietf.org/html/rfc5246) The Transport Layer Security (TLS) Protocol Version 1.2
* [RFC5077](http://tools.ietf.org/html/rfc5077) Transport Layer Security (TLS) Session Resumption without Server-Side State
* [RFC5746](http://tools.ietf.org/html/rfc5746) Transport Layer Security (TLS) Renegotiation Indication Extension
* [RFC3207](http://tools.ietf.org/html/rfc3207) SMTP Service Extension for Secure SMTP over Transport Layer Security

JSON examples
=============
*(scroll down to the end of file to see an example of actual JSON output)*

First dump SSL/TLS features from facebook.com's HTTPS service to fb.json

    $ ./sslprobe facebook.com > fb.json
    ...

The `jq` tool (see <http://stedolan.github.io/jq/>) can then be used to slice
and dice the information in our sample `fb.json`.

`jq` is like sed but for [data scientists](http://jeroenjanssens.com/2013/09/19/seven-command-line-tools-for-data-science.html) and journalists.


Extract certificate chain for a single host and protocol:
----
To extract all certificates presented for SSLv3 (second protocol), try:

     $ jq -r '.[0] | .protocols[1] | .certificates[]' fb.json

The contents of fb.json is an array of tests made against one or more
IP addresses that facebook.com resolved to.  Each test is a JSON object
describing that particular test.

`.[0]` extracts the first object (tested IP) in the array in fb.json.

That information is piped to `'.protocols[1]'`, which extracts the object
for the second tested protocol.  For each tested IP address, five protocols
are checked: SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSV1.2 (in that order).
So far we've selected the object for the SSLv3 protocol in the first test.

`.certificates[]` then selects all entries in the certificate array, which
contains PEM-encoded certificates presented by the server for that protocol.

Finally, the `-r` option to jq makes it output raw data instead of JSON.


Inspect the first certificate presented in the TLSv1 protocol:
----
Almost equivalent to the previous example, but this time we also
make use of `openssl x509` to extract information from the certficate.

    $ jq -r '.[] | .protocols[2] | .certificates[0]' fb.json > server.pem
    $ openssl x509 -noout -text < server.pem
    Certificate:
        Data:
	        Version: 3 (0x2)
	        Serial Number:
	            33:b4:f7:da:c2:82:d4:f6:d9:76:88:f3:f4:77:91:06
	        Signature Algorithm: sha1WithRSAEncryption
	        Issuer: C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Secure Server CA - G3
	        Validity
	            Not Before: Apr 11 00:00:00 2013 GMT
	            Not After : Mar  5 23:59:59 2016 GMT
    ...

Merge files and compile report on TLSv1.2 statuses
----
A slightly more advanced example.

    $ ./sslprobe google.com > google.json
    $ ./sslprobe facebook.com > facebook.json
    $ jq '.[] | [ { host: .host,  ip: .ip,  proto: (.protocols[4] | { name: .name,  supported: .supported } ) } ]' google.json facebook.json
    [
	  {
	    "proto": {
	      "supported": true,
	      "name": "TLS 1.2"
	    },
	    "ip": "173.252.110.27",
	    "host": "facebook.com"
	  }
	]
	[
	  {
	    "proto": {
	      "supported": true,
	      "name": "TLS 1.2"
	    },
	    "ip": "173.194.32.9",
	    "host": "google.com"
	  }
	]



Sample JSON output:
====
Here's some sample output from a test against Facebook.
The certificate data was stripped down to reduce output size.

    [
      {
        "ip":"173.252.110.27",
        "port":443,
        "host":"facebook.com",
        "protocols":[
          {
            "name":"SSL 2.0",
            "version":2,
            "supported":false,
            "establishedConnections":1,
            "lastError":"Connection reset by peer",
            "compressionAlgorithm":0,
            "sessionIdBytes":0,
            "cipherSuites":[
            ],
            "cipherSuitePreference":0,
            "certificateChainSize":0,
            "certificates":[
            ]
          },
          {
            "name":"SSL 3.0",
            "version":768,
            "supported":true,
            "establishedConnections":11,
            "lastError":null,
            "compressionAlgorithm":0,
            "sessionIdBytes":32,
            "cipherSuites":[
              { "id":49169,	"name":"TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
              { "id":5,	"name":"RSA_WITH_RC4_128_SHA" },
              { "id":49171,	"name":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
              { "id":49172,	"name":"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
              { "id":47,	"name":"RSA_WITH_AES_128_CBC_SHA" },
              { "id":53,	"name":"RSA_WITH_AES_256_CBC_SHA" },
              { "id":4,	"name":"RSA_WITH_RC4_128_MD5" },
              { "id":49170,	"name":"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
              { "id":10,	"name":"RSA_WITH_3DES_EDE_CBC_SHA" }
            ],
            "cipherSuitePreference":1,
            "extensions":{
              "sni":1,
              "sniNameUnknown":0,
              "sessionTicket":0,
              "secureRenegotiation":1,
              "heartbeat":0,
              "npn":[
                "spdy/3.1",
                "spdy/3",
                "http/1.1"
              ]
            },
            "lastAlert":{
              "level":0,
              "description":0
            },
            "bugs":{
              "brokenTlsExt":0,
              "csLimit":0,
              "forcedCs":0
            },
            "certificateChainSize":4152,
            "certificates":[
                "-----BEGIN CERTIFICATE-----\nMIIFNjCCBB6gAw....-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIF7DCCBNSg...-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIE0.....JjhJ+xr3AAAAAAAA-----END CERTIFICATE-----\n"
            ]
          },
          {
            "name":"TLS 1.0",
            "version":769,
            "supported":true,
            "establishedConnections":11,
            "lastError":null,
            "compressionAlgorithm":0,
            "sessionIdBytes":0,
            "cipherSuites":[
              { "id":49169,	"name":"TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
              { "id":5,	"name":"RSA_WITH_RC4_128_SHA" },
              { "id":49171,	"name":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
              { "id":49172,	"name":"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
              { "id":47,	"name":"RSA_WITH_AES_128_CBC_SHA" },
              { "id":53,	"name":"RSA_WITH_AES_256_CBC_SHA" },
              { "id":4,	"name":"RSA_WITH_RC4_128_MD5" },
              { "id":49170,	"name":"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
              { "id":10,	"name":"RSA_WITH_3DES_EDE_CBC_SHA" }
            ],
            "cipherSuitePreference":1,
            "extensions":{
              "sni":1,
              "sniNameUnknown":0,
              "sessionTicket":1,
              "secureRenegotiation":1,
              "heartbeat":0,
              "npn":[
                "spdy/3.1",
                "spdy/3",
                "http/1.1"
              ]
            },
            "lastAlert":{
              "level":0,
              "description":0
            },
            "bugs":{
              "brokenTlsExt":0,
              "csLimit":0,
              "forcedCs":0
            },
            "certificateChainSize":4152,
            "certificates":[
                "-----BEGIN CERTIFICATE-----\nMIIFNjCCBB6gAw....-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIF7DCCBNSg...-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIE0.....JjhJ+xr3AAAAAAAA-----END CERTIFICATE-----\n"
            ]
          },
          {
            "name":"TLS 1.1",
            "version":770,
            "supported":true,
            "establishedConnections":11,
            "lastError":null,
            "compressionAlgorithm":0,
            "sessionIdBytes":0,
            "cipherSuites":[
              { "id":49171,	"name":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
              { "id":49172,	"name":"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
              { "id":47,	"name":"RSA_WITH_AES_128_CBC_SHA" },
              { "id":53,	"name":"RSA_WITH_AES_256_CBC_SHA" },
              { "id":49169,	"name":"TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
              { "id":5,	"name":"RSA_WITH_RC4_128_SHA" },
              { "id":4,	"name":"RSA_WITH_RC4_128_MD5" },
              { "id":49170,	"name":"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
              { "id":10,	"name":"RSA_WITH_3DES_EDE_CBC_SHA" }
            ],
            "cipherSuitePreference":1,
            "extensions":{
              "sni":1,
              "sniNameUnknown":0,
              "sessionTicket":1,
              "secureRenegotiation":1,
              "heartbeat":0,
              "npn":[
                "spdy/3.1",
                "spdy/3",
                "http/1.1"
              ]
            },
            "lastAlert":{
              "level":0,
              "description":0
            },
            "bugs":{
              "brokenTlsExt":0,
              "csLimit":0,
              "forcedCs":0
            },
            "certificateChainSize":4152,
            "certificates":[
                "-----BEGIN CERTIFICATE-----\nMIIFNjCCBB6gAw....-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIF7DCCBNSg...-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIE0.....JjhJ+xr3AAAAAAAA-----END CERTIFICATE-----\n"
            ]
          },
          {
            "name":"TLS 1.2",
            "version":771,
            "supported":true,
            "establishedConnections":15,
            "lastError":null,
            "compressionAlgorithm":0,
            "sessionIdBytes":0,
            "cipherSuites":[
              { "id":49199,	"name":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
              { "id":49200,	"name":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
              { "id":49171,	"name":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
              { "id":49172,	"name":"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
              { "id":156,	"name":"TLS_RSA_WITH_AES_128_GCM_SHA256" },
              { "id":157,	"name":"TLS_RSA_WITH_AES_256_GCM_SHA384" },
              { "id":47,	"name":"RSA_WITH_AES_128_CBC_SHA" },
              { "id":53,	"name":"RSA_WITH_AES_256_CBC_SHA" },
              { "id":49169,	"name":"TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
              { "id":5,	"name":"RSA_WITH_RC4_128_SHA" },
              { "id":4,	"name":"RSA_WITH_RC4_128_MD5" },
              { "id":49170,	"name":"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
              { "id":10,	"name":"RSA_WITH_3DES_EDE_CBC_SHA" }
            ],
            "cipherSuitePreference":1,
            "extensions":{
              "sni":1,
              "sniNameUnknown":0,
              "sessionTicket":1,
              "secureRenegotiation":1,
              "heartbeat":0,
              "npn":[
                "spdy/3.1",
                "spdy/3",
                "http/1.1"
              ]
            },
            "lastAlert":{
              "level":0,
              "description":0
            },
            "bugs":{
              "brokenTlsExt":0,
              "csLimit":0,
              "forcedCs":0
            },
            "certificateChainSize":4152,
            "certificates":[
                "-----BEGIN CERTIFICATE-----\nMIIFNjCCBB6gAw....-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIF7DCCBNSg...-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIE0.....JjhJ+xr3AAAAAAAA-----END CERTIFICATE-----\n"
            ]
          }
        ]
      }
    ]

