# Developer shortcuts. Everything here is also what CI runs.
#
#   make test     run the end-to-end test suite (fake WordPress site, simulated wp-cli)
#   make lint     ShellCheck on all scripts (warnings fail)
#   make check    both
#   make install  install for the current user (same as: bash install.sh)

SCRIPTS := $(wildcard bin/*) $(wildcard lib/*.sh) $(wildcard checks/*.sh) install.sh tests/run.sh tests/throttle_check.sh tests/stub/wp

.PHONY: test lint check install

test:
	bash tests/run.sh

lint:
	@command -v shellcheck >/dev/null || { echo "shellcheck is not installed (https://www.shellcheck.net)"; exit 1; }
	shellcheck -x -S warning -s bash $(SCRIPTS)

check: lint test

install:
	bash install.sh
