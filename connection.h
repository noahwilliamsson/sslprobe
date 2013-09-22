#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "buf.h"


typedef struct _connection_t connection_t;
typedef int (*connection_callback_t)(connection_t *);
struct _connection_t {
	int fd;
	/* socket family, ip, port */
	struct addrinfo *ai;
	/* last errno */
	int error;
	/* for SNI */
	char *hostname;

	int is_connecting;
	int is_pending_removal;
	struct timeval tv[1];

	size_t bytes_expected;
	buf_t *buf;

	/* private data */
	void *priv;
	connection_callback_t proto_start;
	connection_callback_t proto_step;
	connection_callback_t proto_finish;

	int doing_tls;
	int doing_smtp;
};


int connection_num_connections(void);
void *connection_priv(connection_t *);
void connection_set_callbacks(connection_t *, connection_callback_t, connection_callback_t, connection_callback_t, void *);
connection_t *connection_open(struct addrinfo *, char *);
void connection_finish(connection_t *);
int connection_write(connection_t *, void *, size_t);
void connection_set_expected_bytes(connection_t *, size_t);
int connection_do_io(void);

#endif
