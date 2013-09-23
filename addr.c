/**
 * Name resolution stuff
 *
 */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "addr.h"


static int addr_aicmp(const void *p1, const void *p2) {
	struct addrinfo *a1 = *(struct addrinfo **)p1,
		*a2 = *(struct addrinfo **)p2;

	if(a1->ai_family != a2->ai_family) {
		if(a1->ai_family == PF_INET)
			return -1;
		else
			return 1;
	}

	return memcmp(a1->ai_addr, a2->ai_addr, a1->ai_addrlen);
}

static struct addrinfo *addr_aisort(struct addrinfo *ai0) {
	struct addrinfo **arr, *ai;
	int i, n;

	if(ai0 == NULL) return NULL;

	for(n = 0, ai = ai0; ai; n++, ai = ai->ai_next);

	arr = (struct addrinfo **)malloc(n * sizeof(struct addrinfo *));
	for(i = 0, ai = ai0; ai; i++, ai = ai->ai_next) arr[i] = ai;

	qsort(arr, n, sizeof(struct addrinfo *), addr_aicmp);
	for(i = 0; i < n - 1; i++) arr[i]->ai_next = arr[i + 1];
	arr[i]->ai_next = NULL;

	return arr[0];
}

struct addrinfo *addr_resolve(char *hostname, char *port) {
	struct addrinfo hints = { 0 }, *list;
	int ret;

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(hostname, port, &hints, &list);
	if(ret) {
		syslog(LOG_NOTICE, "DNS lookup of %s:%s failed: %s",
			hostname, port, gai_strerror(ret));
		return NULL;
	}

	/* Helps diffing output from multiple runs: IPv4 first, then IPv6 */
	return addr_aisort(list);
}

int addr_ai2port(struct addrinfo *ai) {
	static char serv[NI_MAXSERV];

	if(getnameinfo(ai->ai_addr, ai->ai_addrlen, NULL, 0,
		serv, 6, NI_NUMERICSERV) < 0)
			return -1;

	return atoi(serv);
}

char *addr_ai2ip(struct addrinfo *ai) {
	static char ip[NI_MAXHOST];

	if(getnameinfo(ai->ai_addr, ai->ai_addrlen, ip, sizeof(ip),
		NULL, 0, NI_NUMERICHOST) < 0)
			return NULL;

	return ip;
}
