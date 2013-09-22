#ifndef X509_H
#define X509_H

#include <stdlib.h>


char *pem_encode(const unsigned char *, size_t, size_t *);
int x509_dump(const unsigned char *, size_t, int);

#endif
