#include "bloom.h"
#include "xxhash.h"

#include <stdlib.h>
#include <string.h>

#define BLOOM_MAGIC UINT64_C(0x424C4F4F4D303031)

static uint32_t read32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read64le(const uint8_t *p) {
    return (uint64_t)p[0]
        | ((uint64_t)p[1] << 8)
        | ((uint64_t)p[2] << 16)
        | ((uint64_t)p[3] << 24)
        | ((uint64_t)p[4] << 32)
        | ((uint64_t)p[5] << 40)
        | ((uint64_t)p[6] << 48)
        | ((uint64_t)p[7] << 56);
}

static void write32le(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static void write64le(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
    p[4] = (uint8_t)(x >> 32);
    p[5] = (uint8_t)(x >> 40);
    p[6] = (uint8_t)(x >> 48);
    p[7] = (uint8_t)(x >> 56);
}

static void bloom_reset_only(bloom_filter *bf) {
    if (!bf) return;
    free(bf->bits);
    bf->bits = NULL;
    bf->bit_count = 0;
    bf->hash_count = 0;
    bf->item_count = 0;
    bf->byte_count = 0;
}

static void bloom_hashes(const bloom_filter *bf, const void *data, size_t len, uint64_t *h1, uint64_t *h2) {
    *h1 = xxh64(data, len, UINT64_C(0x243F6A8885A308D3));
    *h2 = xxh64(data, len, UINT64_C(0x13198A2E03707344));
    if ((*h2 & 1ULL) == 0) *h2 |= 1ULL;
    if (*h1 >= bf->bit_count) *h1 %= bf->bit_count;
    if (*h2 >= bf->bit_count) *h2 %= bf->bit_count;
}

int bloom_init(bloom_filter *bf, uint64_t bit_count, uint32_t hash_count) {
    uint64_t bytes;
    if (!bf || bit_count == 0 || hash_count == 0) return -1;
    bloom_reset_only(bf);
    bf->owns_self = 0;
    bytes = (bit_count + 7U) / 8U;
    if (bytes == 0 || bytes > SIZE_MAX) return -1;
    bf->bits = (uint8_t *)calloc((size_t)bytes, 1);
    if (!bf->bits) return -1;
    bf->bit_count = bit_count;
    bf->hash_count = hash_count;
    bf->item_count = 0;
    bf->byte_count = bytes;
    return 0;
}

BloomFilter *bloom_create(uint64_t bit_count, uint32_t hash_count) {
    BloomFilter *bf = (BloomFilter *)calloc(1, sizeof(*bf));
    if (!bf) return NULL;
    bf->owns_self = 1;
    if (bloom_init(bf, bit_count, hash_count) != 0) {
        free(bf);
        return NULL;
    }
    bf->owns_self = 1;
    return bf;
}

void bloom_free(bloom_filter *bf) {
    int owns;
    if (!bf) return;
    owns = bf->owns_self;
    bloom_reset_only(bf);
    bf->owns_self = 0;
    if (owns) free(bf);
}

void bloom_clear(bloom_filter *bf) {
    if (!bf || !bf->bits) return;
    memset(bf->bits, 0, (size_t)bf->byte_count);
    bf->item_count = 0;
}

int bloom_set_bit(bloom_filter *bf, uint64_t bit_index) {
    if (!bf || !bf->bits || bit_index >= bf->bit_count) return -1;
    bf->bits[bit_index >> 3] |= (uint8_t)(1U << (bit_index & 7U));
    return 0;
}

int bloom_get_bit(const bloom_filter *bf, uint64_t bit_index) {
    if (!bf || !bf->bits || bit_index >= bf->bit_count) return -1;
    return (bf->bits[bit_index >> 3] >> (bit_index & 7U)) & 1U;
}

void bloom_add(bloom_filter *bf, const void *data, size_t len) {
    uint64_t h1, h2, idx;
    uint32_t i;
    if (!bf || !bf->bits) return;
    bloom_hashes(bf, data, len, &h1, &h2);
    for (i = 0; i < bf->hash_count; ++i) {
        idx = (h1 + (uint64_t)i * h2) % bf->bit_count;
        bf->bits[idx >> 3] |= (uint8_t)(1U << (idx & 7U));
    }
    bf->item_count++;
}

int bloom_maybe_contains(const bloom_filter *bf, const void *data, size_t len) {
    uint64_t h1, h2, idx;
    uint32_t i;
    if (!bf || !bf->bits) return 0;
    bloom_hashes(bf, data, len, &h1, &h2);
    for (i = 0; i < bf->hash_count; ++i) {
        idx = (h1 + (uint64_t)i * h2) % bf->bit_count;
        if (((bf->bits[idx >> 3] >> (idx & 7U)) & 1U) == 0) return 0;
    }
    return 1;
}

int bloom_check(const bloom_filter *bf, const void *data, size_t len) {
    return bloom_maybe_contains(bf, data, len);
}

size_t bloom_serial_size(const bloom_filter *bf) {
    if (!bf) return 0;
    return (size_t)(8 + 8 + 4 + 8 + 8 + bf->byte_count);
}

int bloom_serialise(const bloom_filter *bf, uint8_t *buf) {
    size_t off = 0;
    if (!bf || !buf || !bf->bits) return -1;
    write64le(buf + off, BLOOM_MAGIC); off += 8;
    write64le(buf + off, bf->bit_count); off += 8;
    write32le(buf + off, bf->hash_count); off += 4;
    write64le(buf + off, bf->item_count); off += 8;
    write64le(buf + off, bf->byte_count); off += 8;
    memcpy(buf + off, bf->bits, (size_t)bf->byte_count);
    return 0;
}

BloomFilter *bloom_deserialise(const uint8_t *buf) {
    BloomFilter *bf;
    uint64_t bit_count, item_count, byte_count;
    uint32_t hash_count;
    if (!buf) return NULL;
    if (read64le(buf) != BLOOM_MAGIC) return NULL;
    bit_count = read64le(buf + 8);
    hash_count = read32le(buf + 16);
    item_count = read64le(buf + 20);
    byte_count = read64le(buf + 28);
    if (bit_count == 0 || hash_count == 0 || byte_count != (bit_count + 7U) / 8U || byte_count > SIZE_MAX) return NULL;
    bf = bloom_create(bit_count, hash_count);
    if (!bf) return NULL;
    bf->item_count = item_count;
    memcpy(bf->bits, buf + 36, (size_t)bf->byte_count);
    return bf;
}

int bloom_save_fp(const bloom_filter *bf, FILE *fp) {
    size_t sz;
    uint8_t *buf;
    int rc;
    if (!bf || !fp) return -1;
    sz = bloom_serial_size(bf);
    buf = (uint8_t *)malloc(sz);
    if (!buf) return -1;
    rc = bloom_serialise(bf, buf);
    if (rc == 0 && fwrite(buf, 1, sz, fp) != sz) rc = -1;
    free(buf);
    return rc;
}

int bloom_load_fp(bloom_filter *bf, FILE *fp) {
    uint8_t hdr[36];
    uint64_t bit_count, item_count, byte_count;
    uint32_t hash_count;
    if (!bf || !fp) return -1;
    if (fread(hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) return -1;
    if (read64le(hdr) != BLOOM_MAGIC) return -1;
    bit_count = read64le(hdr + 8);
    hash_count = read32le(hdr + 16);
    item_count = read64le(hdr + 20);
    byte_count = read64le(hdr + 28);
    if (bit_count == 0 || hash_count == 0 || byte_count != (bit_count + 7U) / 8U || byte_count > SIZE_MAX) return -1;
    bloom_reset_only(bf);
    bf->owns_self = 0;
    if (bloom_init(bf, bit_count, hash_count) != 0) return -1;
    bf->item_count = item_count;
    return fread(bf->bits, 1, (size_t)bf->byte_count, fp) == bf->byte_count ? 0 : -1;
}

int bloom_save_file(const bloom_filter *bf, const char *path) {
    FILE *fp;
    int rc;
    if (!path) return -1;
    fp = fopen(path, "wb");
    if (!fp) return -1;
    rc = bloom_save_fp(bf, fp);
    fclose(fp);
    return rc;
}

int bloom_load_file(bloom_filter *bf, const char *path) {
    FILE *fp;
    int rc;
    if (!path) return -1;
    fp = fopen(path, "rb");
    if (!fp) return -1;
    rc = bloom_load_fp(bf, fp);
    fclose(fp);
    return rc;
}
