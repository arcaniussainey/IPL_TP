#ifndef BLOOM_H
#define BLOOM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bloom_filter {
    uint64_t bit_count;
    uint32_t hash_count;
    uint64_t item_count;
    uint64_t byte_count;
    uint8_t *bits;
    uint8_t owns_self;
} bloom_filter;

typedef bloom_filter BloomFilter;

int bloom_init(bloom_filter *bf, uint64_t bit_count, uint32_t hash_count);
BloomFilter *bloom_create(uint64_t bit_count, uint32_t hash_count);
void bloom_free(bloom_filter *bf);
void bloom_clear(bloom_filter *bf);
int bloom_set_bit(bloom_filter *bf, uint64_t bit_index);
int bloom_get_bit(const bloom_filter *bf, uint64_t bit_index);
void bloom_add(bloom_filter *bf, const void *data, size_t len);
int bloom_maybe_contains(const bloom_filter *bf, const void *data, size_t len);
int bloom_check(const bloom_filter *bf, const void *data, size_t len);
size_t bloom_serial_size(const bloom_filter *bf);
int bloom_serialise(const bloom_filter *bf, uint8_t *buf);
BloomFilter *bloom_deserialise(const uint8_t *buf);
int bloom_save_fp(const bloom_filter *bf, FILE *fp);
int bloom_load_fp(bloom_filter *bf, FILE *fp);
int bloom_save_file(const bloom_filter *bf, const char *path);
int bloom_load_file(bloom_filter *bf, const char *path);

#ifdef __cplusplus
}
#endif

#endif
