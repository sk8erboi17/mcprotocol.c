CC ?= cc
AR ?= ar
PYTHON ?= python3
CFLAGS ?= -O3
CPPFLAGS ?=
WARNINGS = -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
	-Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Wundef \
	-Wdouble-promotion -Wnull-dereference
API_CFLAGS = $(CFLAGS) -std=c11 -DNDEBUG $(WARNINGS)
MINECRAFT_DATA_ROOT ?= ../minecraft-data
SCHEMA_PROTOCOL_JSON ?= $(MINECRAFT_DATA_ROOT)/data/pc/26.1/protocol.json
SCHEMA_PROTOCOL_OVERLAY ?= schema/overlays/776.json
GENERATED_PROTOCOL ?= 776
EMBEDDED_REPORT ?= generated/mc_protocol_$(GENERATED_PROTOCOL).json
COMPONENT_SCHEMA_ARGS = \
	--component-profile "766:$(MINECRAFT_DATA_ROOT)/data/pc/1.20.5/protocol.json" \
	--component-profile "767:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.1/protocol.json" \
	--component-profile "768:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.3/protocol.json" \
	--component-profile "769:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.4/protocol.json" \
	--component-profile "770:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.5/protocol.json" \
	--component-profile "771:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.6/protocol.json" \
	--component-profile "772:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.8/protocol.json" \
	--component-profile "773:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.9/protocol.json" \
	--component-profile "774:$(MINECRAFT_DATA_ROOT)/data/pc/1.21.11/protocol.json" \
	--component-profile "775:$(MINECRAFT_DATA_ROOT)/data/pc/26.1/protocol.json" \
	--component-profile "776:$(MINECRAFT_DATA_ROOT)/data/pc/26.1/protocol.json"
FUZZ_CC ?= clang
FUZZ_TARGETS = varint nbt frame compressed_frame dispatcher movement inventory chunk
FUZZ_BINARIES = $(addprefix build/fuzz/,$(FUZZ_TARGETS))
FUZZ_FLAGS = -O1 -g -std=c11 $(WARNINGS) -UNDEBUG -fno-omit-frame-pointer \
	-fsanitize=fuzzer,address,undefined -DMC_FUZZ_LIBFUZZER

.PHONY: all clean shared benchmark benchmark-codec benchmark-network \
	benchmark-baseline coverage coverage-matrix generate generate-check \
	test test-unit test-codec test-stream test-generated test-schema test-amalgamation \
	test-packets test-scoreboard test-player-projection test-envelope test-canonical test-golden test-replay test-property test-connect-profile \
	test-differential test-exports test-asan test-ubsan test-sanitize \
	fuzz-build fuzz-smoke check

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

benchmark: benchmark-codec benchmark-network

benchmark-codec:
	CC="$(CC)" $(PYTHON) benchmark/codec_run.py

benchmark-baseline:
	CC="$(CC)" $(PYTHON) benchmark/codec_run.py --write-baseline

benchmark-network:
	CC="$(CC)" $(PYTHON) benchmark/run.py

coverage-matrix:
	CC="$(CC)" $(PYTHON) tests/coverage_matrix.py

coverage: coverage-matrix
	COVERAGE_CC="$(FUZZ_CC)" $(PYTHON) tests/coverage_test.py

generate:
	$(PYTHON) tools/schema_compiler.py \
		--protocol-json "$(SCHEMA_PROTOCOL_JSON)" \
		--protocol-number "$(GENERATED_PROTOCOL)" \
		--overlay "$(SCHEMA_PROTOCOL_OVERLAY)" \
		--packet play:serverbound:use_item \
		--packet play:serverbound:block_dig \
		$(COMPONENT_SCHEMA_ARGS) \
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
			$(COMPONENT_SCHEMA_ARGS) \
			--embed --api-header api.h --api-source api.c \
			--embedded-report "$(EMBEDDED_REPORT)" \
			--check; \
	else \
		printf '%s\n' "minecraft-data unavailable: embedded-region integrity checked; full regeneration skipped"; \
	fi

test: test-unit test-codec test-packets test-scoreboard test-player-projection test-envelope test-canonical test-golden test-replay test-property test-connect-profile test-stream test-generated test-schema

test-unit: tests/api_test
	./tests/api_test

test-codec: tests/codec_test
	./tests/codec_test

test-packets: tests/typed_packet_test
	./tests/typed_packet_test

test-scoreboard: tests/scoreboard_test
	./tests/scoreboard_test

test-player-projection: tests/player_projection_test
	./tests/player_projection_test

test-envelope: tests/envelope_test
	./tests/envelope_test

test-canonical: tests/canonical_test
	./tests/canonical_test

test-golden:
	CC="$(CC)" $(PYTHON) tests/golden_test.py

test-differential: test-golden
	$(PYTHON) tests/differential_test.py

test-replay: tests/replay_test
	./tests/replay_test

test-property: tests/property_test
	./tests/property_test

test-connect-profile: tests/connect_profile_test
	./tests/connect_profile_test

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

fuzz-build: $(FUZZ_BINARIES)

fuzz-smoke: fuzz-build
	@temporary=$$(mktemp -d); \
	trap 'rm -rf "$$temporary"' EXIT HUP INT TERM; \
	for target in $(FUZZ_TARGETS); do \
		mkdir -p "$$temporary/$$target"; \
		cp tests/corpus/$$target/seed "$$temporary/$$target/seed"; \
		build/fuzz/$$target -runs=128 -max_len=65536 \
			"$$temporary/$$target" >/dev/null 2>&1; \
	done
	@printf '%s\n' "PASS fuzz smoke ($(FUZZ_TARGETS))"

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

tests/typed_packet_test: tests/typed_packet_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/typed_packet_test.c api.c -lz -o $@

tests/scoreboard_test: tests/scoreboard_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/scoreboard_test.c api.c -lz -o $@

tests/player_projection_test: tests/player_projection_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/player_projection_test.c api.c -lz -o $@

tests/envelope_test: tests/envelope_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/envelope_test.c api.c -lz -o $@

tests/canonical_test: tests/canonical_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/canonical_test.c api.c -lz -o $@

tests/replay_test: tests/replay_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/replay_test.c api.c -lz -o $@

tests/property_test: tests/property_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/property_test.c api.c -lz -o $@

tests/generated_test: tests/generated_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/generated_test.c api.c -lz -o $@

tests/connect_profile_test: tests/connect_profile_test.c api.c api.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(WARNINGS) -UNDEBUG \
		-I. tests/connect_profile_test.c api.c -lz -o $@

build/fuzz/%: tests/fuzz/%_fuzz.c tests/fuzz/fuzz_common.h api.c api.h
	@mkdir -p build/fuzz
	$(FUZZ_CC) $(CPPFLAGS) $(FUZZ_FLAGS) -I. $< api.c -lz -o $@

clean:
	rm -f api.o libmcprotocol.a libmcprotocol.so libmcprotocol.dylib \
		tests/api_test tests/codec_test tests/stream_test tests/typed_packet_test \
		tests/scoreboard_test tests/player_projection_test tests/envelope_test tests/canonical_test tests/replay_test tests/property_test \
		tests/generated_test tests/connect_profile_test
	rm -rf build
