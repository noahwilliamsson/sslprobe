/**
 * Various protocol management routines
 *
 * After getting its hands on a struct addrinfo*, the main program
 * initiates a connection to the target host by calling proto_connect().
 *
 * Routines in connection.c then does the actual I/O via proto_process(),
 * and call back into proto_start(), proto_step() and proto_finish().
 *
 * The later routine is used re-initiate probes to the same host
 * aswell as taking care of various issues that comes up.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "addr.h"
#include "connection.h"
#include "proto.h"
#include "smtp.h"
#include "sslv2.h"
#include "tls.h"

#define TAG " \033[1;32;40m--\033[0m "

/* Callbacks */
static int proto_start(connection_t *);
static int proto_step(connection_t *);
static int proto_finish(connection_t *);


char *proto_name(ssl_version_t v) {
	char *name;

	switch(v) {
	case SSLv2: name = "SSL 2.0"; break;
	case SSLv3: name = "SSL 3.0"; break;
	case TLSv10: name = "TLS 1.0"; break;
	case TLSv11: name = "TLS 1.1"; break;
	case TLSv12: name = "TLS 1.2"; break;
	default: name = "NULL"; break;
	}

	return name;
}

char *proto_ver(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	static char version[128];

	sprintf(version, "[%s/%s %d]", proto_name(test->version),
		addr_ai2ip(c->ai), addr_ai2port(c->ai));

	return version;
}

int proto_connect(struct addrinfo *ai, char *hostname, test_t *test) {
	connection_t *c;

	c = connection_open(ai, hostname);
	if(c == NULL) {
		test->error = errno;
		return -1;
	}

	connection_set_callbacks(c, proto_start, proto_step, proto_finish, test);
	return 0;
}

int proto_process(void) {
	do {
		if(connection_do_io() < 0)
			return -1;

	} while(connection_num_connections());

	return 0;
}

static int proto_start(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	int port;

	test->num_connections++;
	fprintf(stderr, "%s" TAG "Starting protocol test\n", proto_ver(c));

	port = addr_ai2port(c->ai);
	if(port == 25) {
		test->state = X_DO_SMTP_EHLO;

	}
	else {
		test->state = X_DO_CLIENTHELLO;
		return proto_step(c);
	}

	return 0;
}

static int proto_step(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);

	switch(test->state) {
	case X_ACCEPTED:
		break;

	case X_DO_SMTP_EHLO:
		switch(smtp_do_ehlo(c)) {
		case -1: return -1; break;
		case 0: return 0; break;
		default:
			test->state = X_DO_SMTP_STARTTLS;
		}
		break;

	case X_DO_SMTP_STARTTLS:
		switch(smtp_do_starttls(c)) {
		case -1: return -1; break;
		case 0: return 0; break;
		default:
			test->state = X_CHECK_SMTP_STARTTLS;
		}
		break;

	case X_CHECK_SMTP_STARTTLS:
		switch(smtp_check_starttls(c)) {
		case -1: return -1; break;
		case 0: return 0; break;
		default:
			test->state = X_DO_CLIENTHELLO;
			return proto_step(c);
		}
		break;

	case X_DO_CLIENTHELLO:
		if(test->version == 2) {
			if(sslv2_do_clienthello(c) < 0)
				return -1;
		}
		else {
			if(tls_do_clienthello(c) < 0)
				return -1;
		}

		/* Wait for header */
		connection_set_expected_bytes(c, test->version == 2? 2: 5);
		test->state = X_GOT_HEADER;
		break;

	case X_GOT_HEADER:
		if(test->version == 2) {

			if(sslv2_handle_header(c) < 0)
				return -1;
			connection_set_expected_bytes(c, test->rec_len);
		}
		else {
			if(tls_handle_header(c) < 0)
				return -1;
			connection_set_expected_bytes(c, test->rec_len);
		}

		test->state = X_GOT_RECORD;
		break;

	case X_GOT_RECORD:
		if(test->version == 2) {
			if(sslv2_handle_record(c) < 0)
				return -1;

			connection_finish(c);
			test->state = X_DONE;
			break;
		}

		if(tls_handle_record(c) < 0)
			return -1;

		if(test->hs_type == 0x0e) {
#ifndef HEARTBLEED
			connection_finish(c);
			test->state = X_DONE;
			break;
#else
			if(!test->ext_heartbeat || tls_do_heartbeat(c, -1) < 0) {
				connection_finish(c);
				test->state = X_DONE;
				break;
			}
#endif
		}

		/* Wait for header */
		connection_set_expected_bytes(c, test->version == 2? 2: 5);
		test->state = X_GOT_HEADER;
		break;

	case X_DONE:
		/* Not reached */
		break;
	}

	return 0;
}

static int proto_finish(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);

	/* Copy last connection error, if any */
	test->error = c->error;

	if(test->version == 2)
		return 0;

	if(test->alert_level == 2) do {
		if(test->alert_desc == 40 && !test->test_cs_preference) {
			/* Have handshake failure (no shared ciphers) */
			if(test->num_ciphers < 2) {
				/* Need at least two supported cipher suites */
				test->has_cs_preference = -1;
				break;
			}

			/**
			 * Test if server has cipher preference by sending two
			 * of the previously selected ciphers in reverse order
			 */
			test->test_cs_preference = 1;
		}
		else if(test->alert_desc == 47 && !test->bugfix_limit_cs) {
			test->bugfix_limit_cs = 128;
			fprintf(stderr, "%s" TAG "Server alerts with "
				"'Illegal parameter', retrying with "
				"limited ciphersuite\n", proto_ver(c));
		}
		else if(test->alert_desc == 47 && !test->bugfix_broken_tlsext) {
			test->bugfix_broken_tlsext = 1;
			fprintf(stderr, "%s" TAG "Server alerts with "
				"'Illegal parameter', retrying with "
				"no TLS extensions\n", proto_ver(c));
		}
		else
			break;

		/* Retry with more limited cipher suite list */
		test->state = X_ACCEPTED;
		test->error = 0;
		test->hs_type = 0;
		test->alert_level = 0;
		test->alert_desc = 0;

		if(proto_connect(c->ai, c->hostname, test) < 0) {
			fprintf(stderr, "%s" TAG "Connection probe failed\n",
				proto_ver(c));
			return -1;
		}

		return 0;
	} while(0);

	/**
	 * Stop testing ciphers on servers which forces ciphers
	 * upon us that wasn't present in our ClientHello.
	 * Also stop if we've tested cipher suite preferences.
	 */
	if(test->bugfix_forced_cs || test->test_cs_preference) {

		return 0;
	}

	if(test->state == X_DONE && test->alert_level == 0) {
		/**
		 * This connection succeeded with its cipher suite so do another
		 * connection with this and previous cipher suites excluded.
		 * This will continue until the server responds with an ALERT
		 * which usually indicates the presented cipher suite doesn't
		 * contain any common ciphers.
		 */
		test->state = X_ACCEPTED;
		test->error = 0;
		test->hs_type = 0;

		if(proto_connect(c->ai, c->hostname, test) < 0) {
			fprintf(stderr, "%s" TAG "Connection probe failed\n",
				proto_ver(c));
			return -1;
		}
	}

	return 0;
}
