#ifndef TLS_H
#define TLS_H

#include "connection.h"


int tls_handle_header(connection_t *);
int tls_handle_record(connection_t *);
int tls_do_clienthello(connection_t *);
int tls_do_heartbeat(connection_t *, ssize_t);

#endif
