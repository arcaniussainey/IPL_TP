#ifndef XXHASH_H
#define XXHASH_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XXH64_PRIME1 UINT64_C(11400714785074694791)
#define XXH64_PRIME2 UINT64_C(14029467366897019727)
#define XXH64_PRIME3 UINT64_C( 1609587929392839161)
#define XXH64_PRIME4 UINT64_C( 9650029242287828579)
#define XXH64_PRIME5 UINT64_C( 2870177450012600261)

#define XXH32_PRIME1 UINT32_C(2654435761)
#define XXH32_PRIME2 UINT32_C(2246822519)
#define XXH32_PRIME3 UINT32_C(3266489917)
#define XXH32_PRIME4 UINT32_C( 668265263)
#define XXH32_PRIME5 UINT32_C( 374761393)

typedef struct {
    uint64_t seed;
    uint64_t acc[4];
    uint8_t buf[32];
    int buflen;
    uint64_t total_len;
} XXH64_state;

void xxh64_reset(XXH64_state *s, uint64_t seed);
void xxh64_update(XXH64_state *s, const void *data, size_t len);
uint64_t xxh64_digest(const XXH64_state *s);
uint64_t xxh64(const void *data, size_t len, uint64_t seed);
uint64_t xxh64_file(const char *path, uint64_t seed);
uint32_t xxh32(const void *data, size_t len, uint32_t seed);

static inline uint64_t xxstream64_hash(const void *data, size_t len, uint64_t seed) {
    return xxh64(data, len, seed);
}

static inline void xxstream64_to_hex(uint64_t v, char out[17]) {
    (void)snprintf(out, 17, "%016llx", (unsigned long long)v);
}

#ifdef __cplusplus
}
#endif

#endif
