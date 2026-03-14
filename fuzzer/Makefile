CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets to auto-test
BUGS = ./bug0 ./bug1 ./bug2 ./bug3 ./bug4 ./bug5
STRATS = strat/*.c

all: fuzzer

# Compile the fuzzer
fuzzer: fuzzer.c help.c $(STRATS) help.h fuzzer.h
	$(CC) $(CFLAGS) -o fuzzer fuzzer.c help.c $(STRATS)

# Clean up
clean:
	rm -f fuzzer
	rm -rf crashes/

# -------------------------------------------------------------
# Argument handling for "make run"
# This block allows you to type: make run ./bug0 10000
# It grabs any arguments after "run" and passes them to the binary.
# -------------------------------------------------------------
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # 1. Get all arguments after "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # 2. Turn them into "do-nothing" targets so Make doesn't halt with an error
  $(eval $(RUN_ARGS):;@:)
endif

run: all
	./fuzzer $(RUN_ARGS)


# Run the fuzzer against all known bug binaries (bug0..bug5)
# Usage: `make run_all` or `make run_all ITERATIONS=5000`
run_all: all
	@for b in $(BUGS); do \
		printf "=== Running $$b ===\n"; \
		./fuzzer $$b ; \
	done

.PHONY: all clean run run_all