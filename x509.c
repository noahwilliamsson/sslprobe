/**
 * Certificate helper routines
 *
 */

#include <stdlib.h>
#include <stdint.h>


static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char header[] = "-----BEGIN CERTIFICATE-----\n";
static char trailer[] = "-----END CERTIFICATE-----\n";


char *pem_encode(const unsigned char *data, size_t len, size_t *outlen) {
	size_t i, j, size;
	uint32_t a, b, c, triple;
	char *output;

	size = 4 * ((len + 2) / 3);
	size += 1 + size / 64 + 28 + 26;

	output = malloc(size + 1);
	if(output == NULL) return NULL;

	for(i = j = 0; i < sizeof(header) - 1; i++)
		output[j++] = header[i];

	for(i = 0; i < len; ) {

		a = i < len ? data[i++] : 0;
		b = i < len ? data[i++] : 0;
		c = i < len ? data[i++] : 0;
		triple = (a << 0x10) + (b << 0x08) + c;

		output[j++] = alphabet[(triple >> 3 * 6) & 0x3F];
		output[j++] = alphabet[(triple >> 2 * 6) & 0x3F];
		output[j++] = alphabet[(triple >> 1 * 6) & 0x3F];
		output[j++] = alphabet[(triple >> 0 * 6) & 0x3F];

		if(i % 48 == 0) output[j++] = '\n';
	}

	switch(len % 3) {
	case 0:
		if(len % 48) output[j++] = '\n';
		break;
	case 1:
		output[j - 2] = '=';
	case 2:
		output[j - 1] = '=';
		output[j++] = '\n';
	}

	for(i = 0; i < sizeof(trailer) - 1; i++)
		output[j++] = trailer[i];

	output[j++] = 0;

	if(outlen) *outlen = size;

	return output;
}

#ifdef DUMP_X509
#include <openssl/x509v3.h>
#include <openssl/objects.h>


int x509_dump(const unsigned char *data, size_t len, int idx) {
	const unsigned char **p = &data;
	unsigned char *str;
	char buf[1024];
	X509 *cert;
	X509_NAME *subject;
	GENERAL_NAMES *list;
	GENERAL_NAME *san;
	int i, n, nid, ret;

	cert = d2i_X509(NULL, p, len);
	if(cert == NULL)
		return -1;

	subject = X509_get_subject_name(cert);
	X509_NAME_oneline(subject, buf, sizeof(buf));
	fprintf(stderr, "Certificate %d: %s\n", idx, buf);

	list = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if(list != NULL) {
		n = sk_GENERAL_NAME_num(list);
		for(i = 0; i < n; i++) {
			san = sk_GENERAL_NAME_value(list, i);
			if(san->type != GEN_DNS) continue;

			ASN1_STRING_to_UTF8(&str, san->d.dNSName);
			fprintf(stderr, "Certificate %d: subjectAltName %d: %s\n", idx, i, str);
			OPENSSL_free(str);
		}
	}

	nid = OBJ_txt2nid("emailAddress");
	ret = X509_NAME_get_text_by_NID(subject, nid, buf, sizeof(buf));
	if(ret != -1) {
		fprintf(stderr, "Certificate %d: email: %s\n", idx, buf);
	}

	fprintf(stderr, "Certificate %d: sig length: %d\n", idx, cert->signature->length);
	fprintf(stderr, "Certificate %d: hash: %02x:%02x:%02x:%02x\n", idx,
		cert->sha1_hash[0], cert->sha1_hash[1], cert->sha1_hash[2], cert->sha1_hash[3]);

	fprintf(stderr, "Certificate %d has akid %p\n", idx, cert->akid);
	if(cert->akid != NULL && ASN1_OCTET_STRING_cmp(cert->skid, cert->akid->keyid) == 0)
		fprintf(stderr, "Certificate %d is self-signed\n", idx);

	X509_free(cert);

	return 0;
}
#endif
