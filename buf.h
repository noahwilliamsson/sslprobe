#ifndef BUF_H
#define BUF_H

#include <stdlib.h>


typedef struct {
        size_t size;
        size_t len;
        size_t read_offset;
        unsigned char data[0];
} buf_t;


buf_t *buf_alloc(size_t);
void buf_free(buf_t *);
void buf_clear(buf_t *);
size_t buf_size(buf_t *);
size_t buf_len(buf_t *);
size_t buf_avail(buf_t *);
int buf_append(buf_t *, unsigned char *, size_t);
int buf_append_u8(buf_t *b, unsigned char);
int buf_append_u16(buf_t *b, unsigned short);
int buf_append_u24(buf_t *b, unsigned int);
int buf_append_u32(buf_t *b, unsigned int);
unsigned char *buf_ptr(buf_t *);
unsigned char *buf_read_next(buf_t *, size_t, size_t *);
void buf_read_done(buf_t *);
unsigned char *buf_peek(buf_t *, size_t, size_t);

#endif
