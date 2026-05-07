#include "xxhash.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ROTL64(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define ROTL32(x,r) (((x)<<(r))|((x)>>(32-(r))))

/* ── xxHash-64 ─────────────────────────────────────────────────────────── */

static inline uint64_t rd64(const uint8_t *p) {
    uint64_t v; memcpy(&v, p, 8); return v;  /* LE-native */
}

static uint64_t round64(uint64_t acc, uint64_t inp) {
    acc += inp * XXH64_PRIME2;
    acc  = ROTL64(acc, 31);
    acc *= XXH64_PRIME1;
    return acc;
}

static uint64_t merge_acc(uint64_t h, uint64_t acc) {
    h ^= round64(0, acc);
    h  = h * XXH64_PRIME1 + XXH64_PRIME4;
    return h;
}

void xxh64_reset(XXH64_state *s, uint64_t seed) {
    s->seed      = seed;
    s->acc[0]    = seed + XXH64_PRIME1 + XXH64_PRIME2;
    s->acc[1]    = seed + XXH64_PRIME2;
    s->acc[2]    = seed;
    s->acc[3]    = seed - XXH64_PRIME1;
    s->buflen    = 0;
    s->total_len = 0;
}

void xxh64_update(XXH64_state *s, const void *data, size_t len) {
    const uint8_t *p   = (const uint8_t *)data;
    const uint8_t *end = p + len;
    s->total_len += len;

    if (s->buflen + (int)len < 32) {
        memcpy(s->buf + s->buflen, p, len);
        s->buflen += (int)len;
        return;
    }
    if (s->buflen > 0) {
        int fill = 32 - s->buflen;
        memcpy(s->buf + s->buflen, p, (size_t)fill);
        for (int i = 0; i < 4; i++) s->acc[i] = round64(s->acc[i], rd64(s->buf + i*8));
        p += fill; s->buflen = 0;
    }
    while (p + 32 <= end) {
        for (int i = 0; i < 4; i++) s->acc[i] = round64(s->acc[i], rd64(p + i*8));
        p += 32;
    }
    if (p < end) { s->buflen = (int)(end - p); memcpy(s->buf, p, (size_t)s->buflen); }
}

uint64_t xxh64_digest(const XXH64_state *s) {
    const uint8_t *p   = s->buf;
    const uint8_t *end = s->buf + s->buflen;
    uint64_t h;

    if (s->total_len >= 32) {
        h  = ROTL64(s->acc[0],  1) + ROTL64(s->acc[1],  7)
           + ROTL64(s->acc[2], 12) + ROTL64(s->acc[3], 18);
        h  = merge_acc(h, s->acc[0]);
        h  = merge_acc(h, s->acc[1]);
        h  = merge_acc(h, s->acc[2]);
        h  = merge_acc(h, s->acc[3]);
    } else {
        h = s->seed + XXH64_PRIME5;
    }
    h += s->total_len;

    while (p + 8 <= end) {
        h ^= round64(0, rd64(p));
        h  = ROTL64(h, 27) * XXH64_PRIME1 + XXH64_PRIME4;
        p += 8;
    }
    if (p + 4 <= end) {
        uint32_t v; memcpy(&v, p, 4);
        h ^= (uint64_t)v * XXH64_PRIME1;
        h  = ROTL64(h, 23) * XXH64_PRIME2 + XXH64_PRIME3;
        p += 4;
    }
    while (p < end) {
        h ^= (uint64_t)(*p) * XXH64_PRIME5;
        h  = ROTL64(h, 11) * XXH64_PRIME1;
        p++;
    }
    h ^= h >> 33; h *= XXH64_PRIME2;
    h ^= h >> 29; h *= XXH64_PRIME3;
    h ^= h >> 32;
    return h;
}

uint64_t xxh64(const void *data, size_t len, uint64_t seed) {
    XXH64_state s; xxh64_reset(&s, seed); xxh64_update(&s, data, len);
    return xxh64_digest(&s);
}

uint64_t xxh64_file(const char *path, uint64_t seed) {
    FILE *f = fopen(path, "rb"); if (!f) return 0;
    XXH64_state s; xxh64_reset(&s, seed);
    uint8_t buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) xxh64_update(&s, buf, n);
    fclose(f); return xxh64_digest(&s);
}

/* ── xxHash-32 ─────────────────────────────────────────────────────────── */

static inline uint32_t rd32(const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}

uint32_t xxh32(const void *data, size_t len, uint32_t seed) {
    const uint8_t *p   = (const uint8_t *)data;
    const uint8_t *end = p + len;
    uint32_t h32;

    if (len >= 16) {
        uint32_t v1 = seed + XXH32_PRIME1 + XXH32_PRIME2;
        uint32_t v2 = seed + XXH32_PRIME2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - XXH32_PRIME1;
        while (p + 16 <= end) {
            v1 = ROTL32(v1 + rd32(p   ) * XXH32_PRIME2, 13) * XXH32_PRIME1;
            v2 = ROTL32(v2 + rd32(p+ 4) * XXH32_PRIME2, 13) * XXH32_PRIME1;
            v3 = ROTL32(v3 + rd32(p+ 8) * XXH32_PRIME2, 13) * XXH32_PRIME1;
            v4 = ROTL32(v4 + rd32(p+12) * XXH32_PRIME2, 13) * XXH32_PRIME1;
            p += 16;
        }
        h32 = ROTL32(v1, 1)+ROTL32(v2, 7)+ROTL32(v3,12)+ROTL32(v4,18);
    } else {
        h32 = seed + XXH32_PRIME5;
    }
    h32 += (uint32_t)len;

    while (p + 4 <= end) {
        h32 += rd32(p) * XXH32_PRIME3;
        h32  = ROTL32(h32, 17) * XXH32_PRIME4;
        p   += 4;
    }
    while (p < end) {
        h32 += (uint32_t)(*p) * XXH32_PRIME5;
        h32  = ROTL32(h32, 11) * XXH32_PRIME1;
        p++;
    }
    h32 ^= h32 >> 15; h32 *= XXH32_PRIME2;
    h32 ^= h32 >> 13; h32 *= XXH32_PRIME3;
    h32 ^= h32 >> 16;
    return h32;
}
