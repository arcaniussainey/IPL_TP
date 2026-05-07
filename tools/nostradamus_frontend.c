/*
 * nostradamus_frontend.c
 *
 * Given a diamond file and one or more documents, compute an addendum that
 * steers H(document || addendum) to the diamond's root hash.
 *
 * Steps:
 *   1. Normalise document to block_size boundaries (zero-pad).
 *   2. Hash document blocks with advance() to get h_doc.
 *   3. Brute-force a "connector" nonce C such that advance(h_doc, C) == leaf[i]
 *      (use the diamond's bloom filter to avoid querying all 2^D leaves each try).
 *   4. Follow the diamond path leaf[i] → root, collecting link nonces.
 *   5. Write:  <original document> || <zero-padding> || C
 *              || link_nonce[0] || link_nonce[1] || ... || link_nonce[D-1]
 *      to outfile.  H of the full output == root_hash.
 *
 * Compile: gcc -O2 -o nostradamus_frontend nostradamus_frontend.c bloom.c xxhash.c
 * Usage:   ./nostradamus_frontend <diamond_file> <doc1> [doc2 ...] <out_suffix>
 *          For each doc, writees <doc>.addendum
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bloom.h"
#include "xxhash.h"

#define MAGIC "NSTD"
typedef struct { char magic[4]; uint32_t depth,block_size,leaf_count,root_hash; } DmdHeader;
typedef struct { uint64_t nonce_l,nonce_r; uint32_t parent_hash; uint8_t _pad[4]; } LinkEntry;

typedef struct {
    DmdHeader  hdr;
    uint32_t  *leaf_hashes;
    LinkEntry **links;       /* links[level][pair] */
    BloomFilter *bf;
} Diamond;

/* xxh32 of 8-byte nonce with state as seed – matches nostradamus.cu */
static uint32_t advance(uint32_t state, uint64_t nonce) {
    return xxh32(&nonce, sizeof(nonce), state);
}

static Diamond *diamond_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    Diamond *d = (Diamond *)calloc(1, sizeof(Diamond));
    fread(&d->hdr, sizeof(DmdHeader), 1, f);
    if (memcmp(d->hdr.magic, MAGIC, 4)) { fprintf(stderr,"bad magic\n"); fclose(f); free(d); return NULL; }

    d->leaf_hashes = (uint32_t *)malloc(d->hdr.leaf_count * sizeof(uint32_t));
    fread(d->leaf_hashes, sizeof(uint32_t), d->hdr.leaf_count, f);

    int depth = (int)d->hdr.depth;
    d->links = (LinkEntry **)malloc(depth * sizeof(LinkEntry*));
    for (int l = 0; l < depth; l++) {
        uint32_t n_pairs = d->hdr.leaf_count >> (l+1);
        d->links[l] = (LinkEntry *)malloc(n_pairs * sizeof(LinkEntry));
        fread(d->links[l], sizeof(LinkEntry), n_pairs, f);
    }
    size_t bsz; fread(&bsz, sizeof(size_t), 1, f);
    uint8_t *bbuf = (uint8_t *)malloc(bsz);
    fread(bbuf, 1, bsz, f);
    d->bf = bloom_deserialise(bbuf); // write bloom filter
    free(bbuf); fclose(f);
    return d;
}

static void diamond_free(Diamond *d) {
    free(d->leaf_hashes);
    for (int l = 0; l < (int)d->hdr.depth; l++) free(d->links[l]);
    free(d->links); bloom_free(d->bf); free(d);
}

/* Hash a document file as a sequence of block_size blocks */
static uint32_t hash_file_blocks(const char *path, uint32_t block_size, uint32_t seed) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    uint8_t *block = (uint8_t *)calloc(1, block_size);
    uint32_t state = seed;
    size_t n;
    while ((n = fread(block, 1, block_size, f)) > 0) {
        if (n < block_size) memset(block + n, 0, block_size - n);
        uint64_t nonce; memcpy(&nonce, block, sizeof(uint64_t));
        state = advance(state, nonce);
    }
    free(block); fclose(f);
    return state;
}

/* Given leaf index, collect nonces on path to root */
static void collect_path(const Diamond *d, uint32_t leaf_idx, uint64_t *path_nonces) {
    uint32_t idx = leaf_idx;
    for (int l = 0; l < (int)d->hdr.depth; l++) {
        uint32_t pair = idx / 2;
        int side = (int)(idx % 2);  /* 0=left 1=right */
        path_nonces[l] = side ? d->links[l][pair].nonce_r : d->links[l][pair].nonce_l;
        idx = pair;
    }
}

static int process_document(const Diamond *d, const char *doc_path) {
    uint32_t h_doc = hash_file_blocks(doc_path, d->hdr.block_size, 0);
    printf("  h_doc = %08X\n", h_doc);

    /* brute-force connector nonce */
    uint32_t hit_leaf = 0; uint64_t connector = 0; int found = 0;
    for (uint64_t nonce = 0; nonce < 0xFFFFFFFFFFFFULL && !found; nonce++) {
        uint32_t h = advance(h_doc, nonce);
        /* quick bloom check */
        if (bloom_check(d->bf, &h, sizeof(uint32_t))) {
            /* verify against leaf table */
            for (uint32_t li = 0; li < d->hdr.leaf_count; li++) {
                if (d->leaf_hashes[li] == h) {
                    connector = nonce; hit_leaf = li; found = 1;
                    break;
                }
            }
        }
        if (nonce % 1000000 == 0) printf("  ... tried %llu nonces\n", (unsigned long long)nonce);
    }
    if (!found) { fprintf(stderr,"  connector not found!\n"); return -1; }
    printf("  connector=%016llX  leaf=%u\n", (unsigned long long)connector, hit_leaf);

    /* collect path nonces */
    uint64_t *path = (uint64_t *)malloc(d->hdr.depth * sizeof(uint64_t));
    collect_path(d, hit_leaf, path);

    /* write addendum file */
    char outpath[4096]; snprintf(outpath, sizeof(outpath), "%s.addendum", doc_path);
    FILE *fin = fopen(doc_path, "rb");
    FILE *fout = fopen(outpath, "wb");
    if (!fin || !fout) { perror("open"); free(path); return -1; }

    /* copy original */
    uint8_t buf[4096]; size_t n;
    long doc_bytes = 0;
    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) { fwrite(buf, 1, n, fout); doc_bytes += n; }
    fclose(fin);

    /* zero-pad to block boundary */
    long pad = ((doc_bytes + d->hdr.block_size - 1) / d->hdr.block_size) * d->hdr.block_size - doc_bytes;
    uint8_t *zeros = (uint8_t *)calloc(1, d->hdr.block_size);
    if (pad) fwrite(zeros, 1, (size_t)pad, fout);

    /* connector nonce */
    fwrite(&connector, sizeof(uint64_t), 1, fout);
    /* diamond path nonces */
    fwrite(path, sizeof(uint64_t), d->hdr.depth, fout);
    fclose(fout); free(zeros); free(path);
    printf("  Written: %s (root_hash=%08X)\n", outpath, d->hdr.root_hash);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr,"usage: %s <diamond> <doc> [doc2 ...]\n",argv[0]); return 1; }
    Diamond *d = diamond_load(argv[1]); // read header from file
    if (!d) return 1;
    printf("Diamond loaded: depth=%u leaves=%u root=%08X\n",
           d->hdr.depth, d->hdr.leaf_count, d->hdr.root_hash); 
    for (int i = 2; i < argc; i++) {
        printf("Processing: %s\n", argv[i]);
        process_document(d, argv[i]);
    }
    diamond_free(d);
    return 0;
}
