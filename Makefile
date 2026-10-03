BEND ?= bend

.PHONY: check test build clean

check:
	@for file in src/*.bend src/merkle/*.bend tests/*.bend examples/*.bend; do \
		BEND_NO_TELEMETRY=1 $(BEND) $$file --check-only >/dev/null || exit 1; \
	done

test: check
	BEND=$(BEND) ./scripts/test.sh

build: check
	BEND_NO_TELEMETRY=1 $(BEND) examples/basic.bend -o bend-merkle-example

clean:
	rm -f bend-merkle-example bend-merkle-example.c bend-merkle-example.js bend-merkle-example.mjs bend-merkle-example.gpu
