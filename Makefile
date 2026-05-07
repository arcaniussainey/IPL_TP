CC ?= gcc
MPICC ?= mpicc
NVCC ?= nvcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -pedantic -Iinclude
NVCCFLAGS ?= -O2 -Iinclude
BIN := bin
COMMON := src/bloom.c src/xxhash.c
APPS := $(BIN)/nostradamus $(BIN)/nostradamus_frontend $(BIN)/cracker
TESTS := $(BIN)/test_bloom $(BIN)/test_xxhash
CRACKER_SRC := tools/cracker/cracker.c tools/cracker/md5_original.c
MD5_HELPERS_SRC := tools/cracker/md5helpers.c tools/cracker/md5_original.c

all: $(APPS) $(TESTS)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/nostradamus: tools/nostradamus.c $(COMMON) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN)/nostradamus_frontend: tools/nostradamus_frontend.c $(COMMON) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN)/cracker: $(CRACKER_SRC) tools/cracker/md5.h tools/cracker/global.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $(CRACKER_SRC)

$(BIN)/md5helpers: $(MD5_HELPERS_SRC) tools/cracker/md5helpers.h tools/cracker/md5.h tools/cracker/global.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $(MD5_HELPERS_SRC)

$(BIN)/mpi_xxhash: tools/mpi_xxhash.c $(COMMON) | $(BIN)
	$(MPICC) $(CFLAGS) -o $@ $^

$(BIN)/nostradamus_gpu: tools/nostradamus_gpu.cu $(COMMON) | $(BIN)
	$(CC) $(CFLAGS) -c -o $(BIN)/bloom.o src/bloom.c
	$(CC) $(CFLAGS) -c -o $(BIN)/xxhash.o src/xxhash.c
	$(NVCC) $(NVCCFLAGS) -o $@ tools/nostradamus_gpu.cu $(BIN)/bloom.o $(BIN)/xxhash.o

$(BIN)/test_xxhash: tests/test_xxhash.c src/xxhash.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN)/test_bloom: tests/test_bloom.c $(COMMON) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

mpi: $(BIN)/mpi_xxhash

gpu: $(BIN)/nostradamus_gpu

md5helpers: $(BIN)/md5helpers

test: all
	./$(BIN)/test_xxhash
	./$(BIN)/test_bloom

clean:
	rm -rf $(BIN)

.PHONY: all mpi gpu md5helpers test clean
