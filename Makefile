CC ?= cc
ARCH ?= x86-64-v3

CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -D_DEFAULT_SOURCE
ifneq ($(strip $(ARCH)),)
CFLAGS += -march=$(ARCH)
endif
CFLAGS += -Isrc

LDFLAGS ?=
LDLIBS ?=

SRC = src/proxyto.c
BIN = proxyto

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
DESTDIR ?=

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(BINDIR)/proxyto
	install -Dm644 man/proxyto.1 $(DESTDIR)$(MANDIR)/man1/proxyto.1

.PHONY: all clean install
