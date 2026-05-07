#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bloom.h"

int main(void) {
    bloom_filter bf = {0};
    BloomFilter *bf2;
    uint8_t *buf;
    size_t sz;
    const char *a = "alpha";
    const char *b = "beta";
    const char *c = "gamma";
    if (bloom_init(&bf, 8192, 5) != 0) return 1;
    bloom_add(&bf, a, strlen(a));
    bloom_add(&bf, b, strlen(b));
    if (!bloom_maybe_contains(&bf, a, strlen(a))) return 2;
    if (!bloom_check(&bf, b, strlen(b))) return 3;
    sz = bloom_serial_size(&bf);
    buf = (uint8_t *)malloc(sz);
    if (!buf) return 4;
    if (bloom_serialise(&bf, buf) != 0) return 5;
    bf2 = bloom_deserialise(buf);
    free(buf);
    if (!bf2) return 6;
    if (!bloom_check(bf2, a, strlen(a))) return 7;
    if (bloom_save_file(&bf, "/tmp/test_bloom.bin") != 0) return 8;
    if (bloom_maybe_contains(bf2, c, strlen(c))) { }
    bloom_free(&bf);
    bloom_free(bf2);
    puts("bloom ok");
    return 0;
}
