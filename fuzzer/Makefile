CC = gcc
CFLAGS = -Wall -Wextra -g

all: fuzzer

# Compile the fuzzer
fuzzer: fuzzer.c help.c help.h
	$(CC) $(CFLAGS) -o fuzzer fuzzer.c help.c

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

.PHONY: all clean run