# Weak-key (small-d) EC detector. Build with:
#   taskset -c 0 nice -n 19 make -j1
# Override compiler/flags for the comparison runs, e.g.:
#   taskset -c 0 nice -n 19 make -j1 CC=clang CFLAGS="-O2 -march=native -Wall"
CC      ?= gcc
CFLAGS  ?= -O3 -march=native -Wall -Wno-unused-function -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS := -lgmp -lcrypto -lm

SRC = src/curves.c src/field_fast.c src/point_fast.c src/point_gmp.c \
      src/babytable.c src/bsgs.c src/tsv.c src/openssl_ref.c src/main.c
OBJ = $(SRC:.c=.o)
BIN = weakkey

.PHONY: all clean selftest

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

selftest: $(BIN)
	./$(BIN) selftest --targets ../common/targets.tsv --answers ../common/answers.tsv --max 100000000

clean:
	rm -f $(OBJ) $(BIN)
