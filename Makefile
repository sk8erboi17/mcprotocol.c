CC ?= cc
AR ?= ar
CFLAGS ?= -O3
CPPFLAGS ?=
WARNINGS = -Wall -Wextra -Wpedantic -Wconversion -Wshadow
API_CFLAGS = $(CFLAGS) -std=c11 -DNDEBUG $(WARNINGS)

.PHONY: all clean shared benchmark

all: libmcprotocol.a

api.o: api.c api.h
	$(CC) $(CPPFLAGS) $(API_CFLAGS) -c api.c -o $@

libmcprotocol.a: api.o
	$(AR) rcs $@ $^

shared: api.c api.h
	@if [ "$$(uname -s)" = Darwin ]; then \
		$(CC) $(CPPFLAGS) $(API_CFLAGS) -fPIC -dynamiclib api.c -lz -o libmcprotocol.dylib; \
	else \
		$(CC) $(CPPFLAGS) $(API_CFLAGS) -fPIC -shared api.c -lz -o libmcprotocol.so; \
	fi

benchmark:
	CC="$(CC)" python3 benchmark/run.py

clean:
	rm -f api.o libmcprotocol.a libmcprotocol.so libmcprotocol.dylib
