/*
 * nostradamus_gpu.cu -- CUDA backend for building XXHash Nostradamus diamonds.
 *
 * Builds the same NSTD diamond format consumed by tools/nostradamus_frontend.c:
 *   - leaf hashes
 *   - per-level link nonces
 *   - serialized bloom filter over the leaves
 *
 * Compile with Makefile:
 *   make bin/nostradamus_gpu
 *
 * Compile manually:
 *   mkdir -p bin
 *   gcc -O2 -std=c11 -Wall -Wextra -pedantic -Iinclude -c -o bin/bloom.o src/bloom.c
 *   gcc -O2 -std=c11 -Wall -Wextra -pedantic -Iinclude -c -o bin/xxhash.o src/xxhash.c
 *   nvcc -O2 -Iinclude -o bin/nostradamus_gpu tools/nostradamus_gpu.cu bin/bloom.o bin/xxhash.o
 *
 * Usage:
 *   ./bin/nostradamus_gpu <diamond_file> [depth] [seed]
 *
 * Example:
 *   ./bin/nostradamus_gpu demo.diamond 20
 *   ./bin/nostradamus_frontend demo.diamond document.txt
 *
 * Defaults:
 *   depth = 20, producing 2^20 leaves
 *   seed  = 0x4E53544458584833
 */
#include "bloom.h"
#include "xxhash.h"

#include <cuda_runtime.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC "NSTD"
#define DEFAULT_DEPTH 20u
#define DEFAULT_SEED UINT64_C(0x4E53544458584833)
#define BLOOM_BITS_PER_LEAF 16u
#define BLOOM_HASHES 7u
#define NSTD_BLOCK_SIZE 8u
#define CUDA_BLOCK_THREADS 256u
#define SMIX_GAMMA UINT64_C(0x9E3779B97F4A7C15)

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

static __host__ __device__ uint32_t rotl32_u(uint32_t x, unsigned r) {
    return (x << r) | (x >> (32u - r));
}

static __host__ __device__ uint32_t rotr32_u(uint32_t x, unsigned r) {
    return (x >> r) | (x << (32u - r));
}

static __host__ __device__ uint64_t splitmix_value(uint64_t seed, uint64_t call_index) {
    uint64_t z = seed + SMIX_GAMMA * (call_index + 1u);
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static __host__ __device__ uint32_t mul_inv32_u(uint32_t x) {
    uint32_t y = x;
    y *= 2u - x * y;
    y *= 2u - x * y;
    y *= 2u - x * y;
    y *= 2u - x * y;
    y *= 2u - x * y;
    return y;
}

static __host__ __device__ uint32_t unxor_right_u(uint32_t x, unsigned shift) {
    for (unsigned s = shift; s < 32u; s <<= 1u) x ^= x >> s;
    return x;
}

static __host__ __device__ uint32_t xxh32_8(uint64_t nonce, uint32_t seed) {
    uint32_t lo = (uint32_t)nonce;
    uint32_t hi = (uint32_t)(nonce >> 32);
    uint32_t h = seed + XXH32_PRIME5 + 8u;
    h = rotl32_u(h + lo * XXH32_PRIME3, 17) * XXH32_PRIME4;
    h = rotl32_u(h + hi * XXH32_PRIME3, 17) * XXH32_PRIME4;
    h ^= h >> 15;
    h *= XXH32_PRIME2;
    h ^= h >> 13;
    h *= XXH32_PRIME3;
    h ^= h >> 16;
    return h;
}

static __host__ __device__ uint32_t xxh32_unavalanche_u(uint32_t x) {
    x = unxor_right_u(x, 16);
    x *= mul_inv32_u(XXH32_PRIME3);
    x = unxor_right_u(x, 13);
    x *= mul_inv32_u(XXH32_PRIME2);
    x = unxor_right_u(x, 15);
    return x;
}

static __host__ __device__ uint64_t nonce_for_target_u(uint32_t state, uint32_t target,
                                                       uint32_t low_word) {
    uint32_t h0 = state + XXH32_PRIME5 + 8u;
    uint32_t h1 = rotl32_u(h0 + low_word * XXH32_PRIME3, 17) * XXH32_PRIME4;
    uint32_t pre2 = rotr32_u(xxh32_unavalanche_u(target) * mul_inv32_u(XXH32_PRIME4), 17);
    uint32_t high_word = (pre2 - h1) * mul_inv32_u(XXH32_PRIME3);
    return (uint64_t)low_word | ((uint64_t)high_word << 32);
}

__global__ void make_leaves_kernel(uint32_t *leaves, uint64_t *candidate_nonces,
                                   uint32_t leaf_count, uint64_t seed) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= leaf_count) return;
    uint64_t nonce = splitmix_value(seed, idx);
    candidate_nonces[idx] = nonce;
    leaves[idx] = xxh32_8(nonce, 0);
}

__global__ void make_links_kernel(const uint32_t *cur, uint32_t *next, LinkEntry *links,
                                  uint32_t pairs, uint64_t seed, uint64_t call_base) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= pairs) return;

    uint32_t parent = (uint32_t)splitmix_value(seed, call_base + (uint64_t)idx * 3u);
    uint32_t low_l = (uint32_t)splitmix_value(seed, call_base + (uint64_t)idx * 3u + 1u);
    uint32_t low_r = (uint32_t)splitmix_value(seed, call_base + (uint64_t)idx * 3u + 2u);
    uint64_t nonce_l = nonce_for_target_u(cur[idx * 2u], parent, low_l);
    uint64_t nonce_r = nonce_for_target_u(cur[idx * 2u + 1u], parent, low_r);

    links[idx].parent_hash = parent;
    links[idx].nonce_l = nonce_l;
    links[idx].nonce_r = nonce_r;
    links[idx]._pad[0] = links[idx]._pad[1] = links[idx]._pad[2] = links[idx]._pad[3] = 0;
    next[idx] = parent;
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

static int cuda_ok(cudaError_t err, const char *what) {
    if (err == cudaSuccess) return 1;
    fprintf(stderr, "%s: %s\n", what, cudaGetErrorString(err));
    return 0;
}

static void free_links(LinkEntry **links, uint32_t depth) {
    if (!links) return;
    for (uint32_t i = 0; i < depth; i++) free(links[i]);
    free(links);
}

static int write_diamond(const char *path, const uint32_t *leaves, LinkEntry **links,
                         uint32_t depth, uint32_t root_hash, const bloom_filter *bf) {
    FILE *f;
    DmdHeader hdr;
    size_t bloom_size;
    uint8_t *bloom_buf;
    uint32_t leaf_count = UINT32_C(1) << depth;

    f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }

    memcpy(hdr.magic, MAGIC, sizeof(hdr.magic));
    hdr.depth = depth;
    hdr.block_size = NSTD_BLOCK_SIZE;
    hdr.leaf_count = leaf_count;
    hdr.root_hash = root_hash;

    if (fwrite(&hdr, sizeof(hdr), 1, f) != 1 ||
        fwrite(leaves, sizeof(*leaves), leaf_count, f) != leaf_count) {
        fclose(f);
        return -1;
    }

    for (uint32_t level = 0; level < depth; level++) {
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
    uint32_t *d_cur = NULL;
    uint32_t *d_next = NULL;
    uint64_t *candidate_nonces = NULL;
    uint64_t *d_candidate_nonces = NULL;
    LinkEntry **links = NULL;
    LinkEntry *d_links = NULL;
    bloom_filter bf = {0};
    uint64_t call_base;
    uint32_t root_hash = 0;
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
    leaves = (uint32_t *)malloc((size_t)leaf_count * sizeof(*leaves));
    candidate_nonces = (uint64_t *)malloc((size_t)leaf_count * sizeof(*candidate_nonces));
    links = (LinkEntry **)calloc(depth, sizeof(*links));
    if (!leaves || !candidate_nonces || !links) {
        fprintf(stderr, "allocation failed\n");
        goto done;
    }

    for (uint32_t level = 0; level < depth; level++) {
        uint32_t pairs = leaf_count >> (level + 1u);
        links[level] = (LinkEntry *)malloc((size_t)pairs * sizeof(**links));
        if (!links[level]) {
            fprintf(stderr, "allocation failed\n");
            goto done;
        }
    }

    if (!cuda_ok(cudaMalloc((void **)&d_cur, (size_t)leaf_count * sizeof(*d_cur)), "cudaMalloc leaves") ||
        !cuda_ok(cudaMalloc((void **)&d_next, (size_t)(leaf_count / 2u) * sizeof(*d_next)), "cudaMalloc next") ||
        !cuda_ok(cudaMalloc((void **)&d_candidate_nonces, (size_t)leaf_count * sizeof(*d_candidate_nonces)), "cudaMalloc candidates")) {
        goto done;
    }

    printf("building GPU diamond: depth=%u leaves=%u seed=%016llX\n",
           depth, leaf_count, (unsigned long long)seed);

    {
        uint32_t grid = (leaf_count + CUDA_BLOCK_THREADS - 1u) / CUDA_BLOCK_THREADS;
        make_leaves_kernel<<<grid, CUDA_BLOCK_THREADS>>>(d_cur, d_candidate_nonces, leaf_count, seed);
        if (!cuda_ok(cudaGetLastError(), "make_leaves_kernel launch") ||
            !cuda_ok(cudaDeviceSynchronize(), "make_leaves_kernel")) {
            goto done;
        }
    }

    if (!cuda_ok(cudaMemcpy(leaves, d_cur, (size_t)leaf_count * sizeof(*leaves),
                            cudaMemcpyDeviceToHost), "copy leaves") ||
        !cuda_ok(cudaMemcpy(candidate_nonces, d_candidate_nonces,
                            (size_t)leaf_count * sizeof(*candidate_nonces),
                            cudaMemcpyDeviceToHost), "copy candidates")) {
        goto done;
    }

    if (bloom_init(&bf, (uint64_t)leaf_count * BLOOM_BITS_PER_LEAF, BLOOM_HASHES) != 0) {
        fprintf(stderr, "bloom allocation failed\n");
        goto done;
    }
    for (uint32_t i = 0; i < leaf_count; i++) bloom_add(&bf, &leaves[i], sizeof(leaves[i]));

    call_base = leaf_count;
    for (uint32_t level = 0; level < depth; level++) {
        uint32_t count = leaf_count >> level;
        uint32_t pairs = count >> 1u;
        uint32_t grid = (pairs + CUDA_BLOCK_THREADS - 1u) / CUDA_BLOCK_THREADS;
        printf("level %u: %u pairs\n", level, pairs);
        fflush(stdout);

        if (!cuda_ok(cudaMalloc((void **)&d_links, (size_t)pairs * sizeof(*d_links)), "cudaMalloc links")) {
            goto done;
        }
        make_links_kernel<<<grid, CUDA_BLOCK_THREADS>>>(d_cur, d_next, d_links, pairs, seed, call_base);
        if (!cuda_ok(cudaGetLastError(), "make_links_kernel launch") ||
            !cuda_ok(cudaDeviceSynchronize(), "make_links_kernel") ||
            !cuda_ok(cudaMemcpy(links[level], d_links, (size_t)pairs * sizeof(**links),
                                cudaMemcpyDeviceToHost), "copy links")) {
            goto done;
        }

        cudaFree(d_links);
        d_links = NULL;
        uint32_t *tmp = d_cur;
        d_cur = d_next;
        d_next = tmp;
        call_base += (uint64_t)pairs * 3u;
    }

    if (!cuda_ok(cudaMemcpy(&root_hash, d_cur, sizeof(root_hash), cudaMemcpyDeviceToHost),
                 "copy root")) {
        goto done;
    }

    if (write_diamond(argv[1], leaves, links, depth, root_hash, &bf) != 0) {
        fprintf(stderr, "failed to write %s\n", argv[1]);
        goto done;
    }

    printf("wrote %s\n", argv[1]);
    printf("root_hash=%08X\n", root_hash);
    printf("valid target candidate: nonce=%016llX leaf=0 hash=%08X\n",
           (unsigned long long)candidate_nonces[0], xxh32(&candidate_nonces[0], sizeof(candidate_nonces[0]), 0));
    rc = 0;

done:
    if (d_links) cudaFree(d_links);
    if (d_candidate_nonces) cudaFree(d_candidate_nonces);
    if (d_next) cudaFree(d_next);
    if (d_cur) cudaFree(d_cur);
    bloom_free(&bf);
    free(candidate_nonces);
    free(leaves);
    free_links(links, depth);
    return rc;
}
