/**
 * Networking stuff
 *
 * connection_do_io() is called by proto_process() and contains the
 * I/O loop which calls into a bunch of other proto_*() routines.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include "addr.h"
#include "buf.h"
#include "connection.h"
#include "proto.h"

static connection_t **root;
static int num_connections;


int connection_num_connections(void) {

	return num_connections;
}

void *connection_priv(connection_t *c) {

	return c->priv;
}

void connection_set_callbacks(connection_t *c, connection_callback_t proto_start, connection_callback_t proto_step, connection_callback_t proto_finish, void *priv) {

	c->proto_start = proto_start;
	c->proto_step = proto_step;
	c->proto_finish = proto_finish;
	c->priv = priv;
}

connection_t *connection_open(struct addrinfo *ai, char *hostname) {
	connection_t *c;
	int fd, flags, saved_errno;

	fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(fd < 0) {
		return NULL;
	}

	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) < 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return NULL;
	}

	if(connect(fd, ai->ai_addr, ai->ai_addrlen) && errno != EINPROGRESS) {
		saved_errno = errno;
		syslog(LOG_NOTICE, "connect() to %s (%s) failed: %s",
			hostname, addr_ai2ip(ai), strerror(errno));
		close(fd);
		errno = saved_errno;
		return NULL;
	}

	root = (connection_t **)realloc(root,
				sizeof(connection_t *) * (num_connections + 1));
	if(root == NULL) {
		close(fd);
		return NULL;
	}

	if((c = calloc(1, sizeof(*c))) == NULL) {
		close(fd);
		return NULL;
	}

	c->buf = buf_alloc(32 * 1024);
	if(c->buf == NULL) {
		close(fd);
		free(c);
		return NULL;
	}

	c->fd = fd;
	c->is_connecting = 1;
	c->is_pending_removal = 0;
	gettimeofday(c->tv, NULL);
	c->ai = ai;
	c->hostname = hostname;
	root[num_connections++] = c;

	return c;
}

static void connection_release(connection_t *c) {
	int i;

	buf_free(c->buf);
	close(c->fd);
	free(c);

	for(i = 0; i < num_connections; i++) {
		if(root[i] != c) continue;

		num_connections--;
		root[i] = root[num_connections];
		break;
	}
}

void connection_set_expected_bytes(connection_t *c, size_t num) {

	c->bytes_expected = num;
}

void connection_finish(connection_t *c) {

	c->is_pending_removal = 1;
}

int connection_write(connection_t *c, void *data, size_t len) {
	unsigned char *ptr = (unsigned char *)data;
	ssize_t n;

	while(len > 0) {
		n = send(c->fd, ptr, len, 0);
		if(n > 0) {
			ptr += n;
			len -= n;
			continue;
		}

		if(errno == EINTR || errno == EAGAIN)
			continue;

		c->error = errno;
		syslog(LOG_INFO, "send() to %s (%s) failed: %s",
			c->hostname, addr_ai2ip(c->ai),
			strerror(c->error));
		return -1;
	}

	return 0;
}

static int connection_read(connection_t *c) {
	unsigned char *p;
	size_t len;
	ssize_t n;

	len = c->bytes_expected;
	if(len == 0) {
		len = buf_avail(c->buf);
	}

	if(len == 0) {
		/* Shouldn't happen */
		return 0;
	}

	p = buf_ptr(c->buf);
	n = recv(c->fd, p, len, 0);
	if(n < 0) {
		if(errno == EINTR || errno == EAGAIN)
			return 0;

		c->error = errno;
		return -1;
	}
	else if(n == 0) {
		/* Remote peer shutdown its side */
		c->error = ECONNRESET;
		return -1;
	}

	buf_append(c->buf, p, n); /* only to update internal length */
	if(c->bytes_expected)
		c->bytes_expected -= n;

	return 0;
}

int connection_do_io(void) {
	fd_set rfds, wfds;
	int i, n, ret, elapsed_ms;
	struct timeval tv[1];
	connection_t *c;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	for(i = n = 0; i < num_connections; i++) {
		c = root[i];

		if(c->is_connecting)
			FD_SET(c->fd, &wfds);
		else
			FD_SET(c->fd, &rfds);

		if(c->fd > n)
			n = c->fd;
	}

	tv->tv_sec = 1;
	tv->tv_usec = 0;
	ret = select(n + 1, &rfds, &wfds, NULL, tv);
	if(ret < 0) {
		syslog(LOG_ERR, "select() failed with error: %s", strerror(errno));
		return -1;
	}

	gettimeofday(tv, NULL);
	for(i = 0; i < num_connections; i++) {
		c = root[i];

		elapsed_ms = (tv->tv_sec - c->tv->tv_sec) * 1000;
		elapsed_ms += (tv->tv_usec - c->tv->tv_usec) / 1000;

		if(FD_ISSET(c->fd, &wfds)) {
			socklen_t optlen = sizeof(c->error);

			c->is_connecting = 0;
			getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &c->error, &optlen);
			if(c->error != 0) {
				connection_finish(c);
				continue;
			}

			if(elapsed_ms > 10000)
				syslog(LOG_INFO, "%s Connection to %s succeed after %dms",
					proto_ver(c), c->hostname, elapsed_ms);

			if(c->proto_start(c) < 0)
				connection_finish(c);

			continue;
		}
		else if(c->is_connecting && elapsed_ms >= 35000) {
			c->error = ETIMEDOUT;
			connection_finish(c);
			continue;
		}

		if(!FD_ISSET(c->fd, &rfds)) {
			if(elapsed_ms > 35000) {
				syslog(LOG_INFO, "%s Timeout waiting for data from %s, %dms elapsed",
					proto_ver(c), c->hostname, elapsed_ms);
				c->error = ETIMEDOUT;
				connection_finish(c);
			}

			continue;
		}

		if(connection_read(c) < 0) {
			connection_finish(c);
			continue;
		}

		if(c->bytes_expected > 0) {
			/* need more data */
			continue;
		}

		if(c->proto_step(c) < 0) {
			connection_finish(c);
			continue;
		}
	}

	/* finialize connections in pending removal state */
	for(i = 0; i < num_connections; i++) {
		c = root[i];
		if(c->is_pending_removal == 0)
			continue;

		c->proto_finish(c);
		connection_release(c);
		i--;
	}

	return 0;
}
