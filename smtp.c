/**
 * SMTP STARTTLS
 * http://tools.ietf.org/html/rfc3207
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connection.h"
#include "proto.h"


typedef enum {
	SMTP_DIGIT_1 = 0,
	SMTP_DIGIT_2,
	SMTP_DIGIT_3,
	SMTP_MULTI,
	SMTP_TEXT,
	SMTP_CRLF,
	SMTP_DONE,
} smtp_state_t;


static ssize_t smtp_parse(connection_t *c, int *code, char **reply) {
	char digits[4] = { 0, 0, 0, 0 }, *str;
	smtp_state_t fsm;
	int i, multi;
	unsigned char *p;
	size_t len;

	len = buf_len(c->buf);
	p = buf_peek(c->buf, 0, len);

	*code = -1; *reply = NULL;
	for(i = multi = fsm = 0; i < len && fsm != SMTP_DONE; i++) {
		if(fsm <= SMTP_DIGIT_3 && (*p < '0' || *p > '9')) return -1;
		else if(fsm == SMTP_MULTI && *p != ' ' && *p != '-') return -1;
		else switch(fsm++) {
		case SMTP_DIGIT_1: digits[0] = *p++; break;
		case SMTP_DIGIT_2: digits[1] = *p++; break;
		case SMTP_DIGIT_3: digits[2] = *p++; break;
		case SMTP_MULTI: multi = (*p++ == '-'); break;
		case SMTP_TEXT: if(*p++ != '\n') { fsm--; break; }
			/* fall through if newline */
		case SMTP_CRLF: fsm++; if(multi) fsm = SMTP_DIGIT_1;
			/* fall through if not multiline reply */
		case SMTP_DONE: break;
		}
	}

	if(fsm != SMTP_DONE)
		return 0;

	if(code) *code = atoi(digits);

	p = buf_read_next(c->buf, i, NULL);
	str = calloc(1, i + 1);
	if((*reply = str) != NULL) while(i--) {
		if(p[i] == '\r' || p[i] == '\n') str[i] = ' ';
		else str[i] = p[i];
	}

	buf_read_done(c->buf);

	return 1;
}

int smtp_do_ehlo(connection_t *c) {
	char *reply, ehlo[] = "EHLO foobar\r\n";
	int code;
	ssize_t ret;

	ret = smtp_parse(c, &code, &reply);
	if(ret <= 0) {
		/* error or need more data */
		free(reply);
		return ret;
	}

	fprintf(stderr, "%s SMTP: %s\n", proto_ver(c), reply);
	free(reply);

	/* Verify banner */
	if(code != 220)
		return -1;


	/* Send EHLO */
	if(connection_write(c, ehlo, strlen(ehlo)) < 0)
		return -1;

	return 1;
}

int smtp_do_starttls(connection_t *c) {
	char *reply, starttls[] = "STARTTLS\r\n";
	int code;
	ssize_t ret;

	ret = smtp_parse(c, &code, &reply);
	if(ret <= 0) {
		/* error or need more data */
		free(reply);
		return ret;
	}

	fprintf(stderr, "%s SMTP: %s\n", proto_ver(c), reply);
	free(reply);

	/* Verify EHLO reply */
	if(code != 250)
		return -1;

	/* Send STARTTLS */
	if(connection_write(c, starttls, strlen(starttls)) < 0)
		return -1;

	return 1;
}

int smtp_check_starttls(connection_t *c) {
	char *reply;
	int code;
	ssize_t ret;

	ret = smtp_parse(c, &code, &reply);
	if(ret <= 0) {
		/* error or need more data */
		free(reply);
		return ret;
	}

	fprintf(stderr, "%s SMTP: %s\n", proto_ver(c), reply);
	free(reply);
	if(code != 220)
		return -1;

	return 1;
}
