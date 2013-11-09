/**
 * SSL/TLS protocol and cipher suite scanner with JSON output
 *   -- noah@hack.se, 2013
 *
 * A report is printed on stdout in JSON (it's not ASN.1, but it's simple),
 * suitable for later inspection/processing.
 * Various protocol details are sent to stderr/syslog.
 *
 * Default protocol is https (port 443) but there's support
 * for STARTTLS if the port argument is set to 25.
 *
 * Handshake overview:
 * - Build Client Hello handshake
 *   - Byte 0 is 0x01 (Client Hello)
 *   - Byte 1-3 is length (u24)
 *   - Append 32xu8 random bytes (0..3=UNIX timestamp, 4..31=random)
 *   - Append u8 with length of session ID (0x00 for empty session ID)
 *     - Append any session ID bytes (none for empty session ID)
 *   - Append u16 with number of cipher suites following
 *     - Append u16 with each cipher suite ID
 *   - Append u8 with number of compression methods
 *     - Append u8 with compression method ID (0=no compression, 1=deflate)
 *   - If using extensions, append u16 with extension data length
 *     - For secure renegotiation (RFC5746):
 *       - Append u16 as extension type (0xff, 0x01)
 *       - Append u16 as extension length (0x00, 01)
 *       - Append u8 as reneg ID length (usually 0x00)
 *       - Append reneg ID data (usually none)
 *     - For Server Name Indication:
 *       - Append u16 as extension type (0x00, 0x00)
 *       - Append u16 as extension length (usually 5 + strlen(hostname))
 *       - Append u16 as SNI list length (usually 3 + strlen(hostname))
 *	 - Append u8 as Server Name Type (0x00 for hostnames)
 *	 - Append SNT data (i.e, the hostname)
 *       - Update extension length (if it wasn't calculated immediately)
 *   - Finally length bytes (1-3) as total length - 4 (bytes 0..3 are implicit)
 * - Wrap entire payload above (Client Hello) in TLS record header:
 *   - Byte 0 is u8 with TLS content_type, value 0x16 (Handshake)
 *   - Byte 1..2 is u16 with TLS version (0x300=SSLv3, 0x301=TLSv1, ..)
 *   - Byte 3..4 is u16 with TLS record length, i.e length of above payload
 *   - Byte 5..N is data of above payload
 * - Send data to server!
 *
 * - Read 5 bytes TLS record header (content_type=u8, version=u16, len=u16)
 *   - content_type=0x15 is Alert Protocol (i.e graceful shutdown)
 *   - content_type=0x16 is Handshake Protocol (what we're interested in)
 *   - version field is maximum supported (i.e, can be 0x301 when 0x303 was req)
 * - Read <len> bytes TLS record payload
 * - Iterate over one or more packets in payload
 *   - Inspect 4 bytes packet header (type=u8, len=24)
 *   - Inspect <len> packet payload
 *     - ct=0x16, type=0x02: Server Hello
 *       - ServerHello is much like Client Hello message
 *       - Additional data in ServerHello is TLS extensions
 *     - ct=0x16, type=0x0b: Server Cert
 *     - ct=0x16, type=0x0c: Server Key-Exchange
 *     - ct=0x16, type=0x0d: Server Hello Done
 * - Loop and read a new 5 byte TLS record header
 *
 *
 * Stuff seen on the internet:
 * - Some servers on accept 128 or less cipher suites
 * - Some servers selects a ciphersuite not in ClientHello
 *
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>

#define APPNAME "sslprobe"

#include "addr.h"
#include "cs.h"
#include "proto.h"


static void probe_server(struct addrinfo *, char *);
static void protocol_report(test_t *, int *);

int main(int argc, char **argv) {
	char *port = "443";
	char *hostname;
	struct addrinfo *ai0, *ai;

	if(argc < 2) {
		fprintf(stderr, "Usage: %s <host> [port (= %s)] [output file]\n", argv[0], port);
		return 0;
	}

	hostname = argv[1];
	if(argc == 3)
		port = argv[2];

	if(argc == 4) {
		if(freopen(argv[3], "w", stdout) == NULL)
			return -1;
	}
	#if OPT
	/* hack for xargs */
	else {
		if(freopen(argv[1], "w", stdout) == NULL)
			return -1;
	}
	#endif

	openlog(APPNAME, LOG_PERROR, LOG_USER);
	signal(SIGPIPE, SIG_IGN);

	if((ai0 = addr_resolve(hostname, port)) == NULL)
		return 0;

	if(!strcmp(hostname, addr_ai2ip(ai0)))
		hostname = NULL;

	printf("[\n");
	for(ai = ai0; ai; ai = ai->ai_next) probe_server(ai, hostname);
	printf("]\n");

	return 0;
}

static void probe_server(struct addrinfo *ai, char *hostname) {
	int i, once = 0;
	test_t tests[5] = {
		{ .version = 0x0002 },
		{ .version = 0x0300 },
		{ .version = 0x0301 },
		{ .version = 0x0302 },
		{ .version = 0x0303 }
	};

	printf("  {\n");
	printf("    \"ip\":\"%s\",\n", addr_ai2ip(ai));
	printf("    \"port\":%d,\n", addr_ai2port(ai));
	if(hostname != NULL)
		printf("    \"host\":\"%s\",\n", hostname);
	else
		printf("    \"host\":null,\n");


	/* Fire up new connections to test each protocol */
	fprintf(stderr, "[%s] -- Starting SSL/TLS tests\n",
		addr_ai2ip(ai));
	for(i = 0; i < 5; i++)
		proto_connect(ai, hostname, &tests[i]);

	/* Do protocol negotation and test ciphers */
	proto_process();


	printf("    \"protocols\":[\n");
	for(i = 0; i < 5; i++)
		protocol_report(&tests[i], &once);
	printf("\n    ]\n");

	printf("  }%s\n", ai->ai_next? ",": "");
}

static void protocol_report(test_t *test, int *once) {
	int i, j;
	char *p;

	if((*once)++) printf(",\n");

	printf("      {\n");
	printf("        \"name\":\"%s\",\n", proto_name(test->version));
	printf("        \"version\":%d,\n", test->version);
	printf("        \"supported\":%s,\n", test->num_ciphers? "true": "false");
	printf("        \"establishedConnections\":%d,\n", test->num_connections);
	if(test->error)
		printf("        \"lastError\":\"%s\",\n", strerror(test->error));
	else
		printf("        \"lastError\":null,\n");
	printf("        \"compressionAlgorithm\":%d,\n", test->compression);
	/* Number of session ID bytes */
	printf("        \"sessionIdBytes\":%d,\n", test->resumption);
	printf("        \"cipherSuites\":[\n");
	for(i = 0; i < test->num_ciphers; i++) {
		for(j = 0; j < sizeof(ciphers) / sizeof(*ciphers); j++) {
			if(test->ciphers[i] != ciphers[j].id) continue;
			printf("          { \"id\":%d,\t\"name\":\"%s\" }%s\n",
				ciphers[j].id, ciphers[j].name,
				i < test->num_ciphers - 1? ",": "");
			break;
		}
	}
	printf("        ],\n");
	printf("        \"cipherSuitePreference\":%d,\n", test->has_cs_preference);

	if(test->version != 2) {
		printf("        \"extensions\":{\n");
		printf("          \"sni\":%d,\n", test->ext_sni);
		printf("          \"sniNameUnknown\":%d,\n", test->ext_sni_unknown);
		printf("          \"sessionTicket\":%d,\n", test->ext_tickets);
		printf("          \"secureRenegotiation\":%d,\n", test->ext_reneg);
		printf("          \"npn\":[\n");
		for(i = 0; i < test->num_npn; i++) {
			printf("            \"%s\"%s\n", test->npn[i],
				i < test->num_npn - 1? ",": "");
		}
		printf("          ]\n");
		printf("        },\n");
		printf("        \"lastAlert\":{\n");
		printf("          \"level\":%d,\n", test->alert_level);
		printf("          \"description\":%d\n", test->alert_desc);
		printf("        },\n");
		printf("        \"bugs\":{\n");
		printf("          \"brokenTlsExt\":%d,\n", test->bugfix_broken_tlsext);
		printf("          \"csLimit\":%d,\n", test->bugfix_limit_cs);
		printf("          \"forcedCs\":%d\n", test->bugfix_forced_cs);
		printf("        },\n");
	}

	printf("        \"certificates\":[\n");
	for(i = 0; i < test->num_certs; i++) {
		printf("\"");
		p = test->certs[i];
		while(*p) {
			if(*p == '\n') printf("\\n");
			else printf("%c", *p);
			p++;
		}
		printf("\"%s\n", i < test->num_certs - 1? ",": "");
	}

	printf("        ]\n");
	printf("      }");

	/* Release resources allocated by protocol handlers */
	for(i = 0; i < test->num_npn; i++)
		if(test->npn[i] != NULL) free(test->npn[i]);

	for(i = 0; i < test->num_certs; i++)
		if(test->certs[i] != NULL) free(test->certs[i]);
}
