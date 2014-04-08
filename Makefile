CC = gcc
CFLAGS = -O2 -Wall -ggdb
OBJS = addr.o buf.o connection.o main.o proto.o smtp.o sslv2.o tls.o x509.o

# make X509=1 clean all
ifdef X509
	CFLAGS += -DDUMP_X509
	LDFLAGS = -lcrypto
endif

ifdef HEARTBLEED
	CFLAGS += -DHEARTBLEED
endif

all: $(OBJS)
	$(CC) -o sslprobe $(OBJS) $(LDFLAGS)
clean:
	rm -f $(OBJS) sslprobe
