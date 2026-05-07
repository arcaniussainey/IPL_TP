#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin
cc=${CC:-gcc}
flags=(-O2 -std=c11 -Wall -Wextra -pedantic -Iinclude)
$cc "${flags[@]}" -o bin/test_xxhash tests/test_xxhash.c src/xxhash.c
$cc "${flags[@]}" -o bin/test_bloom tests/test_bloom.c src/bloom.c src/xxhash.c
$cc "${flags[@]}" -o bin/nostradamus tools/nostradamus.c src/bloom.c src/xxhash.c
$cc "${flags[@]}" -o bin/nostradamus_frontend tools/nostradamus_frontend.c src/bloom.c src/xxhash.c
./bin/test_xxhash
./bin/test_bloom
if command -v mpicc >/dev/null 2>&1; then
  mpicc "${flags[@]}" -o bin/mpi_xxhash tools/mpi_xxhash.c src/bloom.c src/xxhash.c
fi
