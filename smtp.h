#ifndef SMTP_H
#define SMTP_H

#include "connection.h"


int smtp_do_ehlo(connection_t *);
int smtp_do_starttls(connection_t *);
int smtp_check_starttls(connection_t *);

#endif
