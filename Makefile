CC ?= cc
AR ?= ar
PYTHON ?= python3
CFLAGS ?= -O3
CPPFLAGS ?=
WARNINGS = -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
API_CFLAGS = $(CFLAGS) -std=c11 -DNDEBUG $(WARNINGS)
MINECRAFT_DATA_ROOT ?= ../minecraft-data
SCHEMA_PROTOCOL_JSON ?= $(MINECRAFT_DATA_ROOT)/data/pc/26.1/protocol.json
SCHEMA_PROTOCOL_OVERLAY ?= schema/overlays/776.json
GENERATED_PROTOCOL ?= 776
EMBEDDED_REPORT ?= generated/mc_protocol_$(GENERATED_PROTOCOL).json

.PHONY: all clean shared benchmark generate generate-check \
	test test-unit test-codec test-stream test-generated test-schema test-amalgamation \
	test-exports test-asan test-ubsan test-sanitize check

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
	$(PYTHON) tools/schema_compiler.py \
		--protocol-json "$(SCHEMA_PROTOCOL_JSON)" \
		--protocol-number "$(GENERATED_PROTOCOL)" \
		--overlay "$(SCHEMA_PROTOCOL_OVERLAY)" \
		--packet play:serverbound:use_item \
		--packet play:serverbound:block_dig \
		--embed --api-header api.h --api-source api.c \
		--embedded-report "$(EMBEDDED_REPORT)"

generate-check:
	$(PYTHON) tools/schema_compiler.py \
		--protocol-number "$(GENERATED_PROTOCOL)" \
		--overlay "$(SCHEMA_PROTOCOL_OVERLAY)" \
		--api-header api.h --api-source api.c \
		--embedded-report "$(EMBEDDED_REPORT)" \
		--verify-embedded
	@if [ -f "$(SCHEMA_PROTOCOL_JSON)" ]; then \
		$(PYTHON) tools/schema_compiler.py \
			--protocol-json "$(SCHEMA_PROTOCOL_JSON)" \
			--protocol-number "$(GENERATED_PROTOCOL)" \
			--overlay "$(SCHEMA_PROTOCOL_OVERLAY)" \
			--packet play:serverbound:use_item \
			--packet play:serverbound:block_dig \
			--embed --api-header api.h --api-source api.c \
			--embedded-report "$(EMBEDDED_REPORT)" \
			--check; \
	else \
		printf '%s\n' "minecraft-data unavailable: embedded-region integrity checked; full regeneration skipped"; \
	fi

test: test-unit test-codec test-stream test-generated test-schema

test-unit: tests/api_test
	./tests/api_test

test-codec: tests/codec_test
	./tests/codec_test

test-stream: tests/stream_test
	./tests/stream_test
	CC="$(CC)" $(PYTHON) tests/stream_network_test.py

test-generated: tests/generated_test
	./tests/generated_test

test-schema:
	$(PYTHON) tests/schema_compiler_test.py

test-amalgamation:
	CC="$(CC)" $(PYTHON) tests/amalgamation_test.py

test-exports:
	CC="$(CC)" $(PYTHON) tests/export_symbols_test.py

test-asan:
	CC="$(CC)" SANITIZERS=address $(PYTHON) tests/sanitizer_test.py

test-ubsan:
	CC="$(CC)" SANITIZERS=undefined $(PYTHON) tests/sanitizer_test.py

test-sanitize:
	CC="$(CC)" SANITIZERS=address,undefined $(PYTHON) tests/sanitizer_test.py

check: all generate-check test test-amalgamation test-exports test-sanitize

tests/api_test: tests/api_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/api_test.c api.c -lz -o $@

tests/codec_test: tests/codec_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/codec_test.c api.c -lz -o $@

tests/stream_test: tests/stream_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/stream_test.c api.c -lz -o $@

tests/generated_test: tests/generated_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/generated_test.c api.c -lz -o $@

clean:
	rm -f api.o libmcprotocol.a libmcprotocol.so libmcprotocol.dylib \
		tests/api_test tests/codec_test tests/stream_test tests/generated_test
