PROG = zkcmp
SRCS = src/zkcmp.c src/crypto.c
OBJS = $(SRCS:.c=.o)

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

CFLAGS += -O2 -Wall -Wextra -Wpedantic
LDLIBS += -lcrypto

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

src/zkcmp.o: src/zkcmp.c src/zkcmp.h
	$(CC) $(CFLAGS) -c -o $@ src/zkcmp.c

src/schnorr.o: src/crypto.c src/zkcmp.h
	$(CC) $(CFLAGS) -c -o $@ src/crypto.c

install: $(PROG)
	install -d $(DESTDIR)$(BINDIR)
	install -m 555 $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)

clean:
	rm -f $(PROG) $(OBJS)

.PHONY: all install clean
