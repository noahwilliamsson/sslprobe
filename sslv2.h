#ifndef SSLV2_H
#define SSLV2_H

#include "connection.h"


int sslv2_do_clienthello(connection_t *);
int sslv2_handle_header(connection_t *);
int sslv2_handle_record(connection_t *);

#endif
