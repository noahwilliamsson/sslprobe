#ifndef ADDR_H
#define ADDR_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


struct addrinfo *addr_resolve(char *, char *);
int addr_ai2port(struct addrinfo *);
char *addr_ai2ip(struct addrinfo *);
int addr_get_num_connections(void);

#endif
