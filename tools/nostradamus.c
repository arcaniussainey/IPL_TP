#include "bloom.h"
#include "xxhash.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC "NSTD"
#define DEFAULT_DEPTH 8u
#define DEFAULT_SEED UINT64_C(0x4E53544458584833)
#define BLOOM_BITS_PER_LEAF 16u
#define BLOOM_HASHES 7u
#define BLOCK_SIZE 8u

typedef struct {
    char magic[4];
    uint32_t depth;
    uint32_t block_size;
    uint32_t leaf_count;
    uint32_t root_hash;
} DmdHeader;

typedef struct {
    uint64_t nonce_l;
    uint64_t nonce_r;
    uint32_t parent_hash;
    uint8_t _pad[4];
} LinkEntry;

static uint32_t advance(uint32_t state, uint64_t nonce) {
    return xxh32(&nonce, sizeof(nonce), state);
}

static uint32_t rotl32(uint32_t x, unsigned r) {
    return (x << r) | (x >> (32u - r));
}

static uint32_t rotr32(uint32_t x, unsigned r) {
    return (x >> r) | (x << (32u - r));
}

static uint64_t splitmix64(uint64_t *x) {
    uint64_t z;
    *x += UINT64_C(0x9E3779B97F4A7C15);
    z = *x;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static uint32_t mul_inv32(uint32_t x) {
    uint32_t y = x;
    y *= 2u - x * y;
    y *= 2u - x * y;
    y *= 2u - x * y;
    y *= 2u - x * y;
    y *= 2u - x * y;
    return y;
}

static uint32_t unxor_right(uint32_t x, unsigned shift) {
    unsigned s;
    for (s = shift; s < 32u; s <<= 1u) x ^= x >> s;
    return x;
}

static uint32_t xxh32_unavalanche(uint32_t x) {
    static uint32_t inv_p2;
    static uint32_t inv_p3;
    if (!inv_p2) {
        inv_p2 = mul_inv32(XXH32_PRIME2);
        inv_p3 = mul_inv32(XXH32_PRIME3);
    }
    x = unxor_right(x, 16);
    x *= inv_p3;
    x = unxor_right(x, 13);
    x *= inv_p2;
    x = unxor_right(x, 15);
    return x;
}

static uint64_t nonce_for_target(uint32_t state, uint32_t target, uint32_t low_word) {
    static uint32_t inv_p3;
    static uint32_t inv_p4;
    uint32_t h0;
    uint32_t h1;
    uint32_t pre2;
    uint32_t high_word;
    uint64_t nonce;

    if (!inv_p3) {
        inv_p3 = mul_inv32(XXH32_PRIME3);
        inv_p4 = mul_inv32(XXH32_PRIME4);
    }

    h0 = state + XXH32_PRIME5 + 8u;
    h1 = rotl32(h0 + low_word * XXH32_PRIME3, 17) * XXH32_PRIME4;
    pre2 = rotr32(xxh32_unavalanche(target) * inv_p4, 17);
    high_word = (pre2 - h1) * inv_p3;
    nonce = (uint64_t)low_word | ((uint64_t)high_word << 32);
    return nonce;
}

static int parse_u32(const char *s, uint32_t lo, uint32_t hi, uint32_t *out) {
    char *end = NULL;
    unsigned long v;
    errno = 0;
    v = strtoul(s, &end, 0);
    if (errno || !end || *end || v < lo || v > hi) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    unsigned long long v;
    errno = 0;
    v = strtoull(s, &end, 0);
    if (errno || !end || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

static void free_links(LinkEntry **links, uint32_t depth) {
    uint32_t i;
    if (!links) return;
    for (i = 0; i < depth; i++) free(links[i]);
    free(links);
}

static int write_diamond(const char *path, const uint32_t *leaves, LinkEntry **links,
                         uint32_t depth, uint32_t root_hash, const bloom_filter *bf) {
    FILE *f;
    DmdHeader hdr;
    size_t bloom_size;
    uint8_t *bloom_buf;
    uint32_t leaf_count = UINT32_C(1) << depth;
    uint32_t level;

    f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }

    memcpy(hdr.magic, MAGIC, sizeof(hdr.magic));
    hdr.depth = depth;
    hdr.block_size = BLOCK_SIZE;
    hdr.leaf_count = leaf_count;
    hdr.root_hash = root_hash;

    if (fwrite(&hdr, sizeof(hdr), 1, f) != 1 ||
        fwrite(leaves, sizeof(*leaves), leaf_count, f) != leaf_count) {
        fclose(f);
        return -1;
    }

    for (level = 0; level < depth; level++) {
        uint32_t pairs = leaf_count >> (level + 1u);
        if (fwrite(links[level], sizeof(**links), pairs, f) != pairs) {
            fclose(f);
            return -1;
        }
    }

    bloom_size = bloom_serial_size(bf);
    bloom_buf = (uint8_t *)malloc(bloom_size);
    if (!bloom_buf) {
        fclose(f);
        return -1;
    }
    if (bloom_serialise(bf, bloom_buf) != 0 ||
        fwrite(&bloom_size, sizeof(bloom_size), 1, f) != 1 ||
        fwrite(bloom_buf, 1, bloom_size, f) != bloom_size) {
        free(bloom_buf);
        fclose(f);
        return -1;
    }

    free(bloom_buf);
    if (fclose(f) != 0) return -1;
    return 0;
}

int main(int argc, char **argv) {
    uint32_t depth = DEFAULT_DEPTH;
    uint64_t seed = DEFAULT_SEED;
    uint32_t leaf_count;
    uint32_t *leaves = NULL;
    uint32_t *cur = NULL;
    uint32_t *next = NULL;
    uint64_t *candidate_nonces = NULL;
    LinkEntry **links = NULL;
    bloom_filter bf = {0};
    uint64_t rng;
    uint32_t level;
    uint32_t i;
    int rc = 1;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: %s <diamond_file> [depth] [seed]\n", argv[0]);
        return 1;
    }
    if (argc > 2 && parse_u32(argv[2], 1, 30, &depth) != 0) {
        fprintf(stderr, "invalid depth: %s\n", argv[2]);
        return 1;
    }
    if (argc > 3 && parse_u64(argv[3], &seed) != 0) {
        fprintf(stderr, "invalid seed: %s\n", argv[3]);
        return 1;
    }

    leaf_count = UINT32_C(1) << depth;
    rng = seed;

    leaves = (uint32_t *)malloc((size_t)leaf_count * sizeof(*leaves));
    cur = (uint32_t *)malloc((size_t)leaf_count * sizeof(*cur));
    next = (uint32_t *)malloc((size_t)(leaf_count / 2u) * sizeof(*next));
    candidate_nonces = (uint64_t *)malloc((size_t)leaf_count * sizeof(*candidate_nonces));
    links = (LinkEntry **)calloc(depth, sizeof(*links));
    if (!leaves || !cur || !next || !candidate_nonces || !links) {
        fprintf(stderr, "allocation failed\n");
        goto done;
    }

    for (level = 0; level < depth; level++) {
        uint32_t pairs = leaf_count >> (level + 1u);
        links[level] = (LinkEntry *)calloc(pairs, sizeof(**links));
        if (!links[level]) {
            fprintf(stderr, "allocation failed\n");
            goto done;
        }
    }

    for (i = 0; i < leaf_count; i++) {
        candidate_nonces[i] = splitmix64(&rng);
        leaves[i] = advance(0, candidate_nonces[i]);
        cur[i] = leaves[i];
    }

    if (bloom_init(&bf, (uint64_t)leaf_count * BLOOM_BITS_PER_LEAF, BLOOM_HASHES) != 0) {
        fprintf(stderr, "bloom allocation failed\n");
        goto done;
    }
    for (i = 0; i < leaf_count; i++) bloom_add(&bf, &leaves[i], sizeof(leaves[i]));

    printf("building diamond: depth=%u leaves=%u seed=%016llX\n",
           depth, leaf_count, (unsigned long long)seed);

    for (level = 0; level < depth; level++) {
        uint32_t count = leaf_count >> level;
        uint32_t pairs = count >> 1u;
        printf("level %u: %u pairs\n", level, pairs);
        fflush(stdout);
        for (i = 0; i < pairs; i++) {
            LinkEntry *link = &links[level][i];
            link->parent_hash = (uint32_t)splitmix64(&rng);
            link->nonce_l = nonce_for_target(cur[i * 2u], link->parent_hash,
                                             (uint32_t)splitmix64(&rng));
            link->nonce_r = nonce_for_target(cur[i * 2u + 1u], link->parent_hash,
                                             (uint32_t)splitmix64(&rng));
            if (advance(cur[i * 2u], link->nonce_l) != link->parent_hash ||
                advance(cur[i * 2u + 1u], link->nonce_r) != link->parent_hash) {
                fprintf(stderr, "internal XXHash inverse check failed\n");
                goto done;
            }
            next[i] = link->parent_hash;
        }
        memcpy(cur, next, (size_t)pairs * sizeof(*cur));
    }

    if (write_diamond(argv[1], leaves, links, depth, cur[0], &bf) != 0) {
        fprintf(stderr, "failed to write %s\n", argv[1]);
        goto done;
    }

    printf("wrote %s\n", argv[1]);
    printf("root_hash=%08X\n", cur[0]);
    printf("valid target candidate: nonce=%016llX leaf=0 hash=%08X\n",
           (unsigned long long)candidate_nonces[0], leaves[0]);
    rc = 0;

done:
    bloom_free(&bf);
    free(candidate_nonces);
    free(next);
    free(cur);
    free(leaves);
    free_links(links, depth);
    return rc;
}
