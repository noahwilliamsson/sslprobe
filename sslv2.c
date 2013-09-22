/**
 * SSLv2 handshake routines for sending and receiving ClientHello
 * and ServerHello, respectively.
 *
 * SSL 0.2 PROTOCOL SPECIFICATION
 * http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
 *
 * Test target:
 * vestjyskbank.dk supports SSLv2
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "cs.h"
#include "connection.h"
#include "proto.h"
#include "x509.h"


int sslv2_do_clienthello(connection_t *c) {
	size_t len;
	unsigned char *p;
	unsigned char v2_clienthello[] = {
		0x80, 0x2e,	// header (record length)
		0x01,		// message type (CLIENT HELLO)
		0x00, 0x02,	// version (0x0002)
		0x00, 0x15,	// cipher specs list length
		0x00, 0x00,	// session ID length
		0x00, 0x10,	// challenge length
		0x01, 0x00, 0x80,	// SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, 0x80,	// SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x03, 0x00, 0x80,	// SSL_CK_RC2_128_CBC_WITH_MD5
		0x04, 0x00, 0x80,	// SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		0x05, 0x00, 0x80,	// SSL_CK_IDEA_128_CBC_WITH_MD5
		0x06, 0x00, 0x40,	// SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, 0xC0,	// SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		0x0D, 0x0A, 0x0D, 0x0A,	// Challenge data (16 bytes)
		0x45, 0x46, 0x47, 0x47, //   Includes a bunch of newlines
		0x49, 0x4a, 0x4b, 0x4c, //   to trick some servers into
		0x4d, 0x4e, 0x4f, 0x50  //   failing early (e.g bordel.se)
	};

	len = sizeof(v2_clienthello);
	p = v2_clienthello;

	if(connection_write(c, p, len) < 0) {
		fprintf(stderr, "%s Failed to send ClientHello\n", proto_ver(c));
		return -1;
	}

	fprintf(stderr, "%s ClientHello: Sent 0x%02zx/%zd bytes\n",
		proto_ver(c), sizeof(v2_clienthello), sizeof(v2_clienthello));

	return 0;
}

int sslv2_handle_header(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	unsigned char *p;

	p = buf_read_next(c->buf, 2, NULL);
	if((p[0] & 0x80) == 0) {
		/* 3 byte headers not used in handshake */
		fprintf(stderr, "%s Unexpected header bytes [0x%02x 0x%02x]\n",
			proto_ver(c), p[0], p[1]);
		return -1;
	}

	test->rec_len = (p[0] & 0x7f) << 8 | p[1];
	fprintf(stderr, "%s Payload length %zd (0x%04zx)\n",
		proto_ver(c), test->rec_len, test->rec_len);
	if(test->rec_len < 11) {
		fprintf(stderr, "%s Payload length %zd too short for ServerHello\n",
			proto_ver(c), test->rec_len);
		return -1;
	}

	buf_read_done(c->buf);

	if((p = buf_peek(c->buf, 0, 5)) != NULL) {
		/* Hack to make SSLv2 fail early for HTTP responses */
		if(p[0] != 4 /* ServerHello */ || (p[3] << 8 | p[4]) != 0x0002)
			return -1;
	}

	return 0;
}

int sslv2_handle_record(connection_t *c) {
	test_t *test = (test_t *)connection_priv(c);
	unsigned char *p;
	int i, j, n;
	size_t version, cert_size, cs_size, id_size;
	cipher_t *cp;

	p = buf_read_next(c->buf, 11, &test->rec_len);
	if(p == NULL) return -1;

	if(p[0] != 4) {
		fprintf(stderr, "%s ServerHello: Not a valid message\n", proto_ver(c));
		return -1;
	}

	version = p[3] << 8 | p[4];
	cert_size = p[5] << 8 | p[6];
	cs_size = p[7] << 8 | p[8];
	id_size = p[9] << 8 | p[10];

	fprintf(stderr, "%s ServerHello: Version 0x%04zx\n", proto_ver(c), version);
	fprintf(stderr, "%s ServerHello: Cert len %zd\n", proto_ver(c), cert_size);
	fprintf(stderr, "%s ServerHello: Cipher suite len %zd\n", proto_ver(c), cs_size);
	fprintf(stderr, "%s ServerHello: Connection ID len %zd\n", proto_ver(c), id_size);
	if(version != 0x0002) return -1;
	if(test->rec_len != cert_size + cs_size + id_size)
		return -1;

	/* Read certificate */
	p = buf_read_next(c->buf, cert_size, &test->rec_len);
	if(p == NULL) return -1;

	test->certs[0] = realloc(test->certs[0], cert_size);
	if(test->certs[0]) {
		test->certs[0] = pem_encode(p, cert_size, NULL);
		test->num_certs = 1;
	}

	/* Read cipher suite */
	p = buf_read_next(c->buf, cs_size, &test->rec_len);
	if(p == NULL) return -1;
	test->num_ciphers = 0;
	for(i = 0; i < cs_size; i += 3) {
		n = p[i] << 16 | p[i+1] << 8 | p[i+2];
		test->ciphers[test->num_ciphers++] = n;

		cp = NULL;
		for(j = 0; j < sizeof(ciphers) / sizeof(cipher_t); j++) {
			if(ciphers[j].id != n) continue;

			cp = &ciphers[j];
			break;
		}

		fprintf(stderr, "%s ServerHello: Cipher 0x%06x (%s)\n",
			proto_ver(c), n, cp? cp->name: "Unknown");
	}

	p = buf_read_next(c->buf, id_size, &test->rec_len);
	if(p == NULL) return -1;

	buf_read_done(c->buf);

	return 0;
}
