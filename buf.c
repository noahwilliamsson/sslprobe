#include <stdio.h>
#include <string.h>

#include "buf.h"


buf_t *buf_alloc(size_t size) {
	buf_t *b;

	b = (buf_t *)calloc(1, sizeof(buf_t) + size);
	b->size = size;

	return b;
}

void buf_free(buf_t *b) {

	free(b);
}

void buf_clear(buf_t *b) {
	b->len = 0;
	b->read_offset = 0;
	memset(b->data, 0, b->size);
}

size_t buf_size(buf_t *b) {

	return b->size;
}

size_t buf_avail(buf_t *b) {

	return b->size - b->len;
}

size_t buf_len(buf_t *b) {

	return b->len;
}

int buf_append(buf_t *b, unsigned char *data, size_t len) {
	if(buf_avail(b) < len)
		return -1;

	memmove(b->data + b->len, data, len);
	b->len += len;

	return 0;
}

int buf_append_u8(buf_t *b, unsigned char value) {

	return buf_append(b, &value, 1);
}

int buf_append_u16(buf_t *b, unsigned short value) {
	unsigned char buf[2];

	buf[0] = (value >> 8) & 0xff;
	buf[1] = (value >> 0) & 0xff;
	return buf_append(b, buf, 2);
}

int buf_append_u24(buf_t *b, unsigned int value) {
	unsigned char buf[3];

	buf[0] = (value >> 16) & 0xff;
	buf[1] = (value >> 8) & 0xff;
	buf[2] = (value >> 0) & 0xff;
	return buf_append(b, buf, 3);
}

int buf_append_u32(buf_t *b, unsigned int value) {
	unsigned char buf[4];

	buf[0] = (value >> 24) & 0xff;
	buf[1] = (value >> 16) & 0xff;
	buf[2] = (value >> 8) & 0xff;
	buf[3] = (value >> 0) & 0xff;
	return buf_append(b, buf, 4);
}

unsigned char *buf_ptr(buf_t *b) {

	return b->data + b->len;
}

unsigned char *buf_read_next(buf_t *b, size_t len, size_t *limit) {
	unsigned char *p;

	if(b->len - b->read_offset < len)
		return NULL;

	if(limit) {
		if(len > *limit)
			return NULL;
		*limit -= len;
	}

	p = b->data + b->read_offset;
	b->read_offset += len;

	return p;
}

void buf_read_done(buf_t *b) {
	b->len -= b->read_offset;
	memmove(b->data, b->data + b->read_offset, b->len);
	b->read_offset = 0;
}

unsigned char *buf_peek(buf_t *b, size_t offset, size_t len) {
	unsigned char *p;

	if(offset + len > b->len)
		return NULL;

	p = b->data + offset;
	return p;
}
