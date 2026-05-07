/*
 * md5_brute.cu  –  GPU brute-force MD5 preimage search.
 *
 * Divides the candidate space [0, |charset|^length) among CUDA threads.
 * Each thread converts its index to a base-|charset| string, computes MD5,
 * and compares with the target.
 *
 * Compile:  nvcc -O2 -o md5_brute md5_brute.cu
 * Usage:    ./md5_brute <hex_md5_target> <charset> <length>
 * Example:  ./md5_brute 5f4dcc3b5aa765d61d8327deb882cf99 abcdefghijklmnopqrstuvwxyz 8
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "md5.h"
#include <cuda_runtime.h>
#include "md5.cu"

#define MAX_LEN    16
#define MAX_CSET   96
#define BLOCK_SIZE 256

/* ── device data ── */
__constant__ uint8_t d_target[16];
__constant__ char    d_charset[MAX_CSET + 1];
__constant__ int     d_clen;
__constant__ int     d_pwlen;

/* ── kernel ── */
__global__ void brute_kernel(uint64_t base, uint64_t total,
                              int *out_found, uint64_t *out_idx)
{
    if (*out_found) return;
    uint64_t idx = base + blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (idx >= base + total) return;

    /* convert index to string (base d_clen, little-endian digits) */
    char cand[MAX_LEN + 1];
    uint64_t tmp = idx;
    for (int i = 0; i < d_pwlen; i++) {
        cand[i] = d_charset[tmp % (uint64_t)d_clen]; // candidate conversion
        tmp /= (uint64_t)d_clen;
    }
    cand[d_pwlen] = '\0';

    uint8_t digest[16];
    md5_hash((const uint8_t *)cand, (uint32_t)d_pwlen, digest);

    int match = 1;
    for (int i = 0; i < 16; i++) if (digest[i] != d_target[i]) { match=0; break; }
    if (match) {
        if (atomicExch(out_found, 1) == 0) { // exchange match index
            *out_idx = idx;
        }
    }
}

/* ── helpers ── */
static int hex_to_bytes(const char *hex, uint8_t *out, int n) {
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + i*2, "%02x", &v) != 1) return -1; // could replace scanf with custom conversion for speed?
        out[i] = (uint8_t)v;
    }
    return 0;
}

static uint64_t ipow64(uint64_t base, int exp) {
    uint64_t r = 1;
    for (int i = 0; i < exp; i++) r *= base;
    return r;
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr,"usage: %s <md5_hex> <charset> <length>\n",argv[0]); return 1; } // validate inputs

    uint8_t target[16];
    if (strlen(argv[1]) != 32 || hex_to_bytes(argv[1], target, 16) < 0) { // validate input is a hash
        fprintf(stderr,"bad md5 hex\n"); return 1;
    }
    const char *charset = argv[2];
    int clen = (int)strlen(charset);
    int pwlen = atoi(argv[3]);
    if (clen < 1 || clen > MAX_CSET || pwlen < 1 || pwlen > MAX_LEN) {
        fprintf(stderr,"charset len 1-%d, password len 1-%d\n", MAX_CSET, MAX_LEN); return 1;
    }

    uint64_t space = ipow64((uint64_t)clen, pwlen); // calc search space size
    printf("Search space: %llu candidates  charset_len=%d  pwlen=%d\n",
           (unsigned long long)space, clen, pwlen);

    cudaMemcpyToSymbol(d_target,  target,  16);
    cudaMemcpyToSymbol(d_charset, charset, (size_t)(clen+1));
    cudaMemcpyToSymbol(d_clen,    &clen,   sizeof(int));
    cudaMemcpyToSymbol(d_pwlen,   &pwlen,  sizeof(int));

    int *d_found; cudaMalloc(&d_found,  sizeof(int));      cudaMemset(d_found, 0, sizeof(int));
    uint64_t *d_idx;   cudaMalloc(&d_idx,    sizeof(uint64_t)); cudaMemset(d_idx, 0, 8);

    const uint64_t BATCH = (uint64_t)BLOCK_SIZE * 65536; /* tune as needed, maximizes saturation */
    int host_found = 0;
    uint64_t hashes_done = 0;
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    for (uint64_t base = 0; base < space && !host_found; base += BATCH) {
        uint64_t todo  = (base + BATCH < space) ? BATCH : (space - base);
        uint32_t grids = (uint32_t)((todo + BLOCK_SIZE - 1) / BLOCK_SIZE);
        brute_kernel<<<grids, BLOCK_SIZE>>>(base, todo, d_found, d_idx);    // dispatch kernel
        cudaDeviceSynchronize();
        hashes_done += todo;
        cudaMemcpy(&host_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
        if (base % (BATCH * 16) == 0)
            printf("  Progress: %llu / %llu\n", (unsigned long long)base,
                   (unsigned long long)space);
    }

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float elapsed_ms = 0.0f;
    cudaEventElapsedTime(&elapsed_ms, start, stop);

    if (host_found) {
        uint64_t idx;
        cudaMemcpy(&idx, d_idx, sizeof(uint64_t), cudaMemcpyDeviceToHost);
        /* recover string on CPU */
        char cand[MAX_LEN + 1]; uint64_t tmp = idx;
        for (int i = 0; i < pwlen; i++) { cand[i]=charset[tmp%clen]; tmp/=clen; } // conversion to base_k
        cand[pwlen]='\0';
        printf("FOUND: \"%s\"  (index %llu)\n", cand, (unsigned long long)idx);
    } else {
        printf("Not found in search space.\n");
    }
    double elapsed_s = (double)elapsed_ms / 1000.0;
    double hashes_per_second = elapsed_s > 0.0 ? (double)hashes_done / elapsed_s : 0.0;
    printf("Hashes/sec: %.2f  (%llu hashes in %.3f seconds)\n",
           hashes_per_second, (unsigned long long)hashes_done, elapsed_s);

    cudaEventDestroy(start); cudaEventDestroy(stop);
    cudaFree(d_found); cudaFree(d_idx);
    return 0;
}
