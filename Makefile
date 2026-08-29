CC ?= cc
AR ?= ar
CFLAGS ?= -O3
CPPFLAGS ?=
WARNINGS = -Wall -Wextra -Wpedantic -Wconversion -Wshadow
API_CFLAGS = $(CFLAGS) -std=c11 -DNDEBUG $(WARNINGS)
MINECRAFT_DATA_ROOT ?= ../minecraft-data
SCHEMA_PROTOCOL_JSON ?= $(MINECRAFT_DATA_ROOT)/data/pc/26.1/protocol.json
SCHEMA_PROTOCOL_OVERLAY ?= schema/overlays/776.json
GENERATED_PROTOCOL ?= 776

.PHONY: all clean shared benchmark generate test

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

generate:
	python3 tools/schema_compiler.py \
		--protocol-json "$(SCHEMA_PROTOCOL_JSON)" \
		--protocol-number "$(GENERATED_PROTOCOL)" \
		--out-dir generated \
		--overlay "$(SCHEMA_PROTOCOL_OVERLAY)" \
		--packet play:serverbound:use_item \
		--packet play:serverbound:block_dig

test: tests/api_test tests/generated_test
	./tests/api_test
	./tests/generated_test

tests/api_test: tests/api_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/api_test.c api.c -lz -o $@

tests/generated_test: tests/generated_test.c generated/mc_protocol_776.c \
		generated/mc_protocol_776.h api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. -Igenerated tests/generated_test.c generated/mc_protocol_776.c \
		api.c -lz -o $@

clean:
	rm -f api.o libmcprotocol.a libmcprotocol.so libmcprotocol.dylib \
		tests/api_test tests/generated_test
