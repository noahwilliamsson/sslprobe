#ifndef PROTO_H
#define PROTO_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "connection.h"


typedef enum {
	X_ACCEPTED = 0,
	X_DO_SMTP_EHLO,
	X_DO_SMTP_STARTTLS,
	X_CHECK_SMTP_STARTTLS,
	X_DO_CLIENTHELLO,
	X_GOT_HEADER,
	X_GOT_RECORD,
	X_DONE
} test_state_t;

typedef enum {
	SSLv2 = 0x0002,
	SSLv3 = 0x0300,
	TLSv10 = 0x301,
	TLSv11 = 0x302,
	TLSv12 = 0x303
} ssl_version_t;

#define TEST_MAX_CIPHERS 512
#define TEST_MAX_CERTS 32
#define TEST_MAX_NPN 32
typedef struct {
	/* Requested TLS version */
	ssl_version_t version;

	/* Internal state */
	test_state_t state;

	/* Last socket error */
	int error;

	/* Number of successful connections */
	int num_connections;

	/* Received TLS header data */
	int rec_contenttype;
	int rec_version;
	size_t rec_len;

	/* Storage for subprotocol Handshake */
	unsigned char hs_type;
	size_t hs_len;

	/* Compression algorithm */
	unsigned char compression;
	/* Number of session ID bytes */
	unsigned char resumption;
	/* Certificate chain */
	int num_certs;
	char *certs[TEST_MAX_CERTS];

	/* Ciphers supported by server */
	int num_ciphers;
	int ciphers[TEST_MAX_CIPHERS];
	int has_cs_preference;
	int test_cs_preference;

	/* If NPN was seen in ServerHello */
	int num_npn;
	char *npn[TEST_MAX_NPN];
	/* If SNI was seen in ServerHello */
	int ext_sni;
	/* If we get "Unrecognized name" */
	int ext_sni_unknown;
	/* If SessionTicket was seen in ServerHello */
	int ext_tickets;
	/* If Re-Negotiation was seen in ServerHello */
	int ext_reneg;

	/* Set if server restricts cipher count to 128 */
	int bugfix_limit_cs;
	/* Set if server breaks on TLS extensions (Oracle HTTP Server 10g) */
	int bugfix_broken_tlsext;
	/* Set if server selects cipher not in ClientHello */
	int bugfix_forced_cs;

	/* Storage for subprotocol Alert */
	int alert_level;
	int alert_desc;
} test_t;


char *proto_name(ssl_version_t);
char *proto_ver(connection_t *);
int proto_connect(struct addrinfo *, char *, test_t *);
int proto_process(void);

#endif
