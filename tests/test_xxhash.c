#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "xxhash.h"

int main(void) {
    const char *s = "hello world";
    XXH64_state st;
    uint64_t a, b;
    char hex[17];
    xxh64_reset(&st, 0);
    xxh64_update(&st, s, 5);
    xxh64_update(&st, s + 5, strlen(s) - 5);
    a = xxh64_digest(&st);
    b = xxh64(s, strlen(s), 0);
    xxstream64_to_hex(a, hex);
    if (a != b) {
        fprintf(stderr, "stream mismatch\n");
        return 1;
    }
    printf("xxh64(hello world)=%s\n", hex);
    return 0;
}
