/**
 * SSLv3/TLSv1 handshake routines called by proto.c
 *
 * Implements ClientHello and the interesting parts of the
 * Handshake and Alert protocol
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "connection.h"
#include "cs.h"
#include "proto.h"
#include "x509.h"

static int tls_handle_alert(connection_t *);
static int tls_handle_hs_serverhello(connection_t *);
static int tls_handle_hs_servercert(connection_t *);
static int tls_handle_hs_hellodone(connection_t *);
static int tls_handle_hs_kex(connection_t *);


int tls_do_clienthello(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	size_t i, j, n, rec_len_offset, hs_len_offset, ext_len_offset;
	unsigned char *p;
	buf_t *b;
	time_t t;

	b = buf_alloc(5 + 16*1024);
	if(b == NULL)
		return -1;

	/* TLS record header */
	buf_append_u8(b, 0x16 /* Content type: Handshake */);
	buf_append_u16(b, test->version);
	rec_len_offset = buf_len(b);
	buf_append_u16(b, 0 /* updating length later */);

	/* TLS Handshake header */
	buf_append_u8(b, 0x01 /* Content type: ClientHello */);
	hs_len_offset = buf_len(b);
	buf_append_u24(b, 0 /* updating length later */);

	/* TLS Handshake: Requested version */
	buf_append_u16(b, test->version);

	/* TLS Handshake: Client random (32 bytes, with first 4 as timestamp) */
	t = time(NULL);
	buf_append_u32(b, t);
	for(i = 0; i < 28/4; i++) buf_append_u32(b, (t >> i) ^ (t << i));

	/* TLS Handshake: Empty session ID */
	buf_append_u8(b, 0);

	/**
	 * Send a list of all ciphers we know about (cs.h)
	 * As soon as the server indicates a handshake failure
	 * we can be relatively sure it was because none of
	 * the ciphers listed in the ClientHello were supported.
	 *
	 * That's how we guess what ciphers a server support.
	 */
	n = 0;
	for(i = 0; i < sizeof(ciphers) / sizeof(cipher_t); i++) {
		for(j = 0; j < test->num_ciphers; j++)
			if(ciphers[i].id == test->ciphers[j]) break;
		if(j != test->num_ciphers) {
			fprintf(stderr, "%s ClientHello: Skipping cipher 0x%04x (%s)\n",
				proto_ver(c), ciphers[i].id, ciphers[i].name);
			continue;
		}

		n++;

		/* Some servers (bredband.com) do alert [2,47] if more than 128 ciphers */
		if(test->bugfix_limit_cs && n == test->bugfix_limit_cs) break;
	}

	fprintf(stderr, "%s ClientHello: Including %zd/%zd ciphers\n",
		proto_ver(c), n, sizeof(ciphers) / sizeof(cipher_t));

	buf_append_u16(b, 2 * n);
	for(i = 0; i < sizeof(ciphers) / sizeof(cipher_t); i++) {
		for(j = 0; j < test->num_ciphers; j++)
			if(ciphers[i].id == test->ciphers[j]) break;
		if(j != test->num_ciphers) {
			continue;
		}

		buf_append_u16(b, ciphers[i].id);
		if(test->bugfix_limit_cs && !--n)
			break;
	}

	/**
	 * Lame detection of CRIME side-channel attack vulnerability
	 * by indicating support for DEFLATE
	 */
	buf_append_u8(b, 2 /* Number of compression methods */);
	buf_append_u8(b, 0x01 /* deflate */);
	buf_append_u8(b, 0x00 /* no compression */);

	/* TLS Extensions */
	ext_len_offset = buf_len(b);
	buf_append_u16(b, 0 /* updating length later */);

	/* Session tickets: http://tools.ietf.org/html/rfc5077 */
	buf_append_u16(b, 0x0023 /* type */);
	buf_append_u16(b, 0x0000 /* length */);

	/* Secure reneg: http://tools.ietf.org/html/rfc5746 */
	buf_append_u16(b, 0xff01 /* type */);
	buf_append_u16(b, 0x0001 /* length */);
	buf_append_u8(b, 0x00 /* empty renegotiated_connection[] */);

	if(c->hostname != NULL) {
		/* SNI */
		buf_append_u16(b, 0x0000 /* type */);
		buf_append_u16(b, 5 + strlen(c->hostname) /* length */);
		buf_append_u16(b, 3 + strlen(c->hostname) /* SNI list length */);
		buf_append_u8(b, 0x00 /* Server Name Type */);
		buf_append_u16(b, strlen(c->hostname) /* Server Name Length */);
		buf_append(b, (unsigned char *)c->hostname, strlen(c->hostname));

		/* NPN (only allowed if also doing SNI) */
		buf_append_u16(b, 0x3374 /* type */);
		buf_append_u16(b, 0x0000 /* length */);
	}

	/* Unregistered 1337 extension just to fuck with NIDS */
	buf_append_u16(b, 0x0539 /* type */);
	buf_append_u16(b, 42 /* length */);
	buf_append(b, (unsigned char *)"id\nuid=0(root) gid=0(root) groups=0(root)\n", 42);


	p = buf_peek(b, rec_len_offset, 2);
	n = buf_len(b) - 5 /* skip TLS record header */;
	p[0] = (n >> 8) & 0xff;
	p[1] = (n >> 0) & 0xff;

	p = buf_peek(b, hs_len_offset, 3);
	n = buf_len(b) - 5 - 4 /* skip TLS handshake header */;
	p[0] = (n >> 16) & 0xff;
	p[1] = (n >> 8) & 0xff;
	p[2] = (n >> 0) & 0xff;

	p = buf_peek(b, ext_len_offset, 2);
	n = buf_len(b) - ext_len_offset - 2 /* skip TLS ext length field */;
	p[0] = (n >> 8) & 0xff;
	p[1] = (n >> 0) & 0xff;

	n = buf_len(b);
	p = buf_peek(b, 0, n);

	if(connection_write(c, p, n) < 0) {
		fprintf(stderr, "%s Failed to send ClientHello\n",
			proto_ver(c));
		return -1;
	}

	fprintf(stderr, "%s ClientHello: Sent 0x%02zx/%zd bytes\n",
		proto_ver(c), buf_len(b), buf_len(b));

	buf_free(b);
	return 0;
}

int tls_handle_header(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	unsigned char *p;

	p = buf_read_next(c->buf, 5, NULL);
	test->rec_contenttype = p[0];
	test->rec_version = p[1] << 8 | p[2];
	test->rec_len = p[3] << 8 | p[4];

	fprintf(stderr, "%s Header [type 0x%02x, version 0x%02x, len 0x%02zx (%zd bytes)]\n",
		proto_ver(c), test->rec_contenttype, test->rec_version,
		test->rec_len, test->rec_len);

	switch(test->rec_contenttype) {
	case 0x15:
	case 0x16:
		break;
	default:
		fprintf(stderr, "%s Header has unexpected content type\n",
			proto_ver(c));
		return -1;
	}

	if(test->rec_len > 16*1024) {
		fprintf(stderr, "%s Header has out-of-spec length\n",
			proto_ver(c));
		return -1;
	}

	if(test->rec_version != test->version) {
		fprintf(stderr, "%s TLS version not supported\n",
			proto_ver(c));
		return -1;
	}

	buf_read_done(c->buf);

	return 0;
}

int tls_handle_record(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	unsigned char *p;

	do {
		if(test->rec_contenttype == 0x15) {
			if(tls_handle_alert(c) < 0)
				return -1;

			/* Consider all alerts fatal */
			return -1;
		}

		p = buf_peek(c->buf, 0, 4);
		if(p == NULL) return -1;
		test->hs_len = p[1] << 16 | p[2] << 8 | p[3];
		fprintf(stderr, "%s Handshake [type 0x%02x, len 0x%04zx (%zd bytes)]\n",
			proto_ver(c), p[0], test->hs_len, test->hs_len);

		if(p[0] > test->hs_type) {
			test->hs_type = p[0];
		}
		else {
			fprintf(stderr, "%s Handshake: Expected type > 0x%02x\n",
				proto_ver(c), test->hs_type);
			return -1;
		}

		switch(p[0]) {
		case 2: /* ServerHello */
			if(tls_handle_hs_serverhello(c) < 0)
				return -1;
			break;
		case 11: /* Server certificate */
			if(tls_handle_hs_servercert(c) < 0)
				return -1;
			break;
		case 12: /* Key exchange */
			if(tls_handle_hs_kex(c) < 0)
				return -1;
			break;
		case 14: /* ServerHello done */
			if(tls_handle_hs_hellodone(c) < 0)
				return -1;
			break;
		default:
			fprintf(stderr, "%s Handshake: Ignoring packet of type 0x%02x\n",
				proto_ver(c), p[0]);
			p = buf_read_next(c->buf, 4, NULL);
			p = buf_read_next(c->buf, test->hs_len, NULL);
			buf_read_done(c->buf);
			break;
		}

	} while(buf_len(c->buf) > 0);

	return 0;
}

/* https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6 */
static int tls_handle_alert(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	unsigned char *p;
	char *level, *desc;

	p = buf_read_next(c->buf, 2, NULL);
	switch(p[0]) {
	case 1: level = "Warning"; break;
	case 2: level = "Fatal error"; break;
	default: level = "Unknown alert"; break;
	}

	switch(p[1]) {
	case 0: desc = "Close notification"; break;
	case 10: desc = "Unknown message"; break;
	case 40: desc = "Handshake failure"; break;
	case 42: desc = "Bad certificate"; break;
	case 47: desc = "Illegal parameter"; break;
	case 49: desc = "Access denied"; break;
	case 110: desc = "Unsupported extension"; break;
	case 112: desc = "Unrecognized name"; break;
	default: desc = "<description unavailable>"; break;
	}

	test->alert_level = p[0];
	test->alert_desc = p[1];

	fprintf(stderr, "%s Alert: Level=0x%02x (%s), description=0x%02x (%s)\n",
		proto_ver(c), p[0], level, p[1], desc);

	buf_read_done(c->buf);

	return 0;
}

static int tls_handle_hs_serverhello(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	int i, len, type, version;
	size_t msg_len;
	unsigned char *p;
	cipher_t *cp;

	if((p = buf_read_next(c->buf, 4, NULL)) == NULL) return -1;
	type = p[0];
	msg_len = p[1] << 16 | p[2] << 8 | p[3];
	if(type != 2 /* ServerHello */)
		return -1;


	if((p = buf_read_next(c->buf, 2, &msg_len)) == NULL) return -1;
	version = p[0] << 8 | p[1];
	fprintf(stderr, "%s ServerHello: [type 0x%02x, len 0x%06zx, version 0x%04x]\n",
		proto_ver(c), type, msg_len, version);

	if(version != test->version) return -1;


	if((p = buf_read_next(c->buf, 32, &msg_len)) == NULL) return -1;
	fprintf(stderr, "%s ServerHello: Timestamp %u\n",
		proto_ver(c), p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);


	if((p = buf_read_next(c->buf, 1, &msg_len)) == NULL) return -1;
	len = test->resumption = p[0];
	fprintf(stderr, "%s ServerHello: Session ID length is 0x%02x\n",
		proto_ver(c), len);

	if((p = buf_read_next(c->buf, len, &msg_len)) == NULL) return -1;


	if((p = buf_read_next(c->buf, 2, &msg_len)) == NULL) return -1;
	cp = NULL;
	for(i = 0; i < sizeof(ciphers) / sizeof(cipher_t); i++) {
		int j;

		if(ciphers[i].id != (p[0] << 8 | p[1]))
			continue;

		/**
		 * Once a server has selected a cipher from the list sent in
		 * ClientHello, we filter that cipher out and make sure we
		 * don't send it again.  Some servers, such as www.unity.se,
		 * includes ciphers in the ServerHello that wasn't present in
		 * ClientHello.  We detect this behavior here to stop testing
		 * cipher support for this server.
		 */
		cp = &ciphers[i];
		for(j = 0; j < test->num_ciphers; j++) {
			if(test->ciphers[j] == cp->id) {
				fprintf(stderr, "%s ServerHello: Selected cipher 0x%04x was not in ClientHello\n",
					proto_ver(c), p[0] << 8 | p[1]);
				test->bugfix_forced_cs = 1;
				break;
			}
		}

		if(j == test->num_ciphers)
			test->ciphers[test->num_ciphers++] = cp->id;
		break;
	}

	fprintf(stderr, "%s ServerHello: Cipher suite 0x%04x (%s)\n",
		proto_ver(c), p[0] << 8 | p[1], cp? cp->name: "Unknown");


	if((p = buf_read_next(c->buf, 1, &msg_len)) == NULL) return -1;
	test->compression = p[0];
	fprintf(stderr, "%s ServerHello: Compression 0x%02x (%s)\n",
		proto_ver(c), p[0],
		p[0] == 0? "None": p[0] == 1? "Deflate": "Unknown");


	if((p = buf_read_next(c->buf, 2, &msg_len)) == NULL) {
		/* No extensions */
		buf_read_done(c->buf);
		fprintf(stderr, "%s ServerHello: No extensions\n",
			proto_ver(c));
		return 0;
	}

	i = p[0] << 8 | p[1];
	while(i > 0) {
		p = buf_read_next(c->buf, 2, &msg_len);
		if(p == NULL) {
			fprintf(stderr, "%s ServerHello: Failed reading 2 bytes of extension type\n", proto_ver(c));
			return -1;
		}

		type = p[0] << 8 | p[1];
		if((p = buf_read_next(c->buf, 2, &msg_len)) == NULL) return -1;
		len = p[0] << 8 | p[1];
		if((p = buf_read_next(c->buf, len, &msg_len)) == NULL) return -1;

		i -= 2 + 2 + len;

		switch(type) {
		case 0x0000:
			/* Server supports SNI */
			test->ext_sni = 1;
			fprintf(stderr, "%s ServerHello: Extension SNI with %d bytes data\n",
				proto_ver(c), len);
			break;
		case 0x0023:
			/**
			 * Server intends to send a NewTicket *after* the handshake
			 * which we never complete fully.. so we're not 100% sure
			 */
			test->ext_tickets = 1;
			fprintf(stderr, "%s ServerHello: Extension TICKETS with %d bytes data\n",
				proto_ver(c), len);
			break;
		case 0x3374:
			/* Server supports NPN, and therefore also SNI */
			test->ext_sni = 1;
			fprintf(stderr, "%s ServerHello: Extension NPN with %d bytes data\n",
				proto_ver(c), len);
			fprintf(stderr, "%s ServerHello: Extension NPN protocols:",
				proto_ver(c));
			test->num_npn = 0;
			while(len-- > 0) {
				int j, bytes;
				char npn[256];

				bytes = *p++;
				for(j = 0; j < bytes && len > 0; j++, len--) npn[j] = *p++;
				npn[j] = 0;
				fprintf(stderr, " [%s]", npn);

				if(test->num_npn < TEST_MAX_NPN) {
					test->npn[test->num_npn] = realloc(test->npn[test->num_npn], j + 1);
					if(test->npn[test->num_npn]) {
						strcpy(test->npn[test->num_npn], npn);
						test->num_npn++;
					}
				}
			}
			fprintf(stderr, "\n");
			break;
		case 0xff01:
			fprintf(stderr, "%s ServerHello: Extension RENEG with %d bytes data [0x%02x]\n",
				proto_ver(c), len, *p);
			if(len != 1 || p[0])
				return -1;
			/* Server supports secure renegotiation */
			test->ext_reneg = 1;
			break;
		default:
			fprintf(stderr, "%s ServerHello: Extension 0x%04x with %d bytes data\n",
				proto_ver(c), type, len);
			break;
		}
	}

	if(msg_len != 0) {
		fprintf(stderr, "%s ServerHello: %zd additional bytes present in packet?!\n",
			proto_ver(c), msg_len);
		return -1;
	}

	buf_read_done(c->buf);

	return 0;
}

static int tls_handle_hs_servercert(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	unsigned char *p;
	int type;
	size_t cert_list_size, cert_size, msg_len;

	if((p = buf_read_next(c->buf, 4, NULL)) == NULL) return -1;
	type = p[0];
	msg_len = p[1] << 16 | p[2] << 8 | p[3];
	fprintf(stderr, "%s Certificate [type 0x%02x, len 0x%06zx]\n",
		proto_ver(c), type, msg_len);

	if((p = buf_read_next(c->buf, 3, &msg_len)) == NULL) return -1;
	cert_list_size = p[0] << 16 | p[1] << 8 | p[2];
	test->num_certs = 0;
	while(msg_len > 0) {
		if((p = buf_read_next(c->buf, 3, &msg_len)) == NULL) return -1;
		cert_size = p[0] << 16 | p[1] << 8 | p[2];

		if((p = buf_read_next(c->buf, cert_size, &msg_len)) == NULL) return -1;

		if(test->num_certs < TEST_MAX_CERTS) {
			if(test->certs[test->num_certs] != NULL)
				free(test->certs[test->num_certs]);
			test->certs[test->num_certs] = pem_encode(p, cert_size, NULL);
			if(test->certs[test->num_certs] != NULL)
				test->num_certs++;
		}
#ifdef X509_DUMP
		{
			char buf[1024];
			FILE *fd;

			x509_dump(p, cert_size, test->num_certs - 1);
			sprintf(buf, "server-%02x-num-%d-len-%zd.crt",
				type, test->num_certs - 1, cert_size);
			fd = fopen(buf, "w");
			if(fd != NULL) {
				fwrite(p, cert_size, 1, fd);
				fclose(fd);
			}
		}
#endif
	}

	buf_read_done(c->buf);

	return 0;
}

static int tls_handle_hs_kex(connection_t *c) {
	int type;
	size_t msg_len;
	unsigned char *p;

	if((p = buf_read_next(c->buf, 4, NULL)) == NULL) return -1;
	type = p[0];
	msg_len = p[1] << 16 | p[2] << 8 | p[3];
	fprintf(stderr, "%s KEX [type 0x%02x, len 0x%06zx]\n",
		proto_ver(c), type, msg_len);

	if((p = buf_read_next(c->buf, msg_len, &msg_len)) == NULL) return -1;

	buf_read_done(c->buf);

	return 0;
}

static int tls_handle_hs_hellodone(connection_t *c) {
	int type;
	size_t msg_len;
	unsigned char *p;

	if((p = buf_read_next(c->buf, 4, NULL)) == NULL) return -1;
	type = p[0];
	msg_len = p[1] << 16 | p[2] << 8 | p[3];
	fprintf(stderr, "%s ServerHello Done: [type 0x%02x, len 0x%06zx]\n",
		proto_ver(c), type, msg_len);

	if((p = buf_read_next(c->buf, msg_len, &msg_len)) == NULL) return -1;

	buf_read_done(c->buf);

	return 0;
}
