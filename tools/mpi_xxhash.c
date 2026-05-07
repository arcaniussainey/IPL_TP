/*
 * mpi_xxhash.c  –  Distributed xxHash preimage table (MPI master/servant).
 *
 * Rank 0  = master:  assigns ranges, collects bloom filters, runs interactive
 *                    query loop.
 * Rank 1+ = servants: compute xxHash64 of password candidates, store in local
 *                     hash table + bloom filter, report to master periodically,
 *                     answer point-lookup queries.
 *
 * Candidate encoding: treat uint64 index as base-|charset|^length password.
 * Each servant receives a contiguous range [start, start+count).
 *
 * MPI message tags:
 *   TAG_ASSIGN  = 1   master to servant: {start u64, count u64, charset, pwlen}
 *   TAG_BLOOM   = 2   servant to master: serialised bloom filter bytes
 *   TAG_QUERY   = 3   master toservant: target hash (u64)
 *   TAG_RESP    = 4   servant to master: {found u8, preimage char[MAX_PW_LEN+1]}
 *   TAG_STOP    = 5   master to servant: shutdown signal
 *   TAG_RETRY   = 6   master internal retry list (not really a tag)
 *
 * Compile: mpicc -O2 -o mpi_xxhash mpi_xxhash.c bloom.c xxhash.c
 * Usage:   mpirun -np <N> ./mpi_xxhash <charset> <pwlen> [bloom_bits] [report_interval]
 */
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/select.h>
#include <unistd.h>
#include "bloom.h"
#include "xxhash.h"

#define TAG_ASSIGN  1
#define TAG_BLOOM   2
#define TAG_QUERY   3
#define TAG_RESP    4
#define TAG_STOP    5

#define MAX_PW_LEN   16
#define MAX_CSET     96
#define LOCAL_TABLE_MAX (1u << 22)   /* 4M entries per servant */

typedef struct { uint64_t hash; char pw[MAX_PW_LEN + 1]; } TableEntry;

/* ── shared helpers ─────────────────────────────────────────────────────── */
static void idx_to_pw(uint64_t idx, const char *charset, int clen, int pwlen, char *out) {
    for (int i = 0; i < pwlen; i++) { out[i] = charset[idx % clen]; idx /= clen; }
    out[pwlen] = '\0';
}

static uint64_t ipow64(uint64_t base, int exp) {
    uint64_t r = 1; for (int i=0;i<exp;i++) r*=base; return r;
}

/* ── master ── */
typedef struct { uint64_t hash; } RetryEntry;

static void master(int nprocs, const char *charset, int pwlen,
                   uint64_t bloom_bits, uint64_t report_interval)
{
    int nservants = nprocs - 1;
    if (nservants == 0) { fprintf(stderr,"need at least 2 ranks\n"); return; }

    int clen = (int)strlen(charset);
    uint64_t total_space = ipow64((uint64_t)clen, pwlen);
    uint64_t per_servant = (total_space + nservants - 1) / nservants;

    /* send assignments */
    for (int r = 1; r <= nservants; r++) {
        uint64_t start = (uint64_t)(r-1) * per_servant;
        uint64_t count = (start + per_servant > total_space)
                       ? (total_space - start) : per_servant;
        /* pack: start(8) count(8) bloom_bits(8) report_interval(8) clen(4) pwlen(4) charset */
        int csz = (int)strlen(charset);
        int bufsz = 8+8+8+8+4+4+csz+1;
        uint8_t *buf = (uint8_t*)malloc(bufsz);
        int off = 0;
        // Copy Data                      Adjust offset
        memcpy(buf+off,&start,8);         off+=8;
        memcpy(buf+off,&count,8);         off+=8;
        memcpy(buf+off,&bloom_bits,8);    off+=8;
        memcpy(buf+off,&report_interval,8); off+=8;
        memcpy(buf+off,&csz,4);           off+=4;
        memcpy(buf+off,&pwlen,4);         off+=4;
        memcpy(buf+off,charset,csz+1);
        MPI_Send(buf, bufsz, MPI_BYTE, r, TAG_ASSIGN, MPI_COMM_WORLD);
        free(buf);
        printf("[master] servant %d assigned [%llu, %llu)\n",
               r,(unsigned long long)start,(unsigned long long)(start+count));
    }

    /* per-servant bloom filters */
    BloomFilter **servant_bf = (BloomFilter **)calloc(nservants+1, sizeof(BloomFilter*));

    /* retry queue */
    uint64_t *retry = NULL; int n_retry = 0, cap_retry = 0;

    printf("[master] Interactive query session. Type a hex hash (16 hex chars) or 'q' to quit.\n");
    fflush(stdout);

    int running = 1;
    while (running) {
        /* poll for incoming bloom updates (non-blocking) */
        MPI_Status status;
        int flag;
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_BLOOM, MPI_COMM_WORLD, &flag, &status);
        while (flag) {
            int count; MPI_Get_count(&status, MPI_BYTE, &count);
            uint8_t *buf = (uint8_t*)malloc(count);
            MPI_Recv(buf, count, MPI_BYTE, status.MPI_SOURCE, TAG_BLOOM,
                     MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            int src = status.MPI_SOURCE;
            if (servant_bf[src]) bloom_free(servant_bf[src]);
            servant_bf[src] = bloom_deserialise(buf);
            free(buf);
            printf("[master] received bloom update from servant %d\n", src);
            fflush(stdout);
            MPI_Iprobe(MPI_ANY_SOURCE, TAG_BLOOM, MPI_COMM_WORLD, &flag, &status);
        }

        /* retry pending queries against freshened bloom filters */
        for (int qi = n_retry-1; qi >= 0; qi--) {
            uint64_t qhash = retry[qi];
            for (int r = 1; r <= nservants; r++) {
                if (!servant_bf[r]) continue;
                if (bloom_check(servant_bf[r], &qhash, sizeof(qhash))) {
                    MPI_Send(&qhash, sizeof(qhash), MPI_BYTE, r, TAG_QUERY, MPI_COMM_WORLD);
                    uint8_t resp[1+MAX_PW_LEN+1];
                    MPI_Recv(resp, sizeof(resp), MPI_BYTE, r, TAG_RESP,
                             MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                    if (resp[0]) {
                        printf("[master] RETRY HIT: hash=%016llX preimage=\"%s\"\n",
                               (unsigned long long)qhash, (char*)(resp+1));
                        /* remove from retry */
                        retry[qi] = retry[--n_retry];
                    }
                    break;
                }
            }
        }

        /* non-blocking stdin check */
        fd_set rfds; FD_ZERO(&rfds); FD_SET(STDIN_FILENO, &rfds);
        struct timeval tv = {0, 50000}; /* 50ms poll */
        int sel = select(STDIN_FILENO+1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        char line[64];
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line,"\n")] = '\0';
        if (line[0]=='q' || line[0]=='Q') { running = 0; break; }

        if (strlen(line) != 16) {
            printf("[master] enter 16 hex digits or 'q'\n"); fflush(stdout); continue;
        }
        uint64_t qhash = (uint64_t)strtoull(line, NULL, 16);

        int found_any = 0;
        for (int r = 1; r <= nservants; r++) {
            if (!servant_bf[r]) continue;
            if (bloom_check(servant_bf[r], &qhash, sizeof(qhash))) {
                MPI_Send(&qhash, sizeof(qhash), MPI_BYTE, r, TAG_QUERY, MPI_COMM_WORLD);
                uint8_t resp[1+MAX_PW_LEN+1];
                MPI_Recv(resp, sizeof(resp), MPI_BYTE, r, TAG_RESP,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                if (resp[0]) {
                    printf("[master] FOUND on servant %d: preimage=\"%s\"\n",
                           r, (char*)(resp+1));
                    found_any = 1; break;
                }
            }
        }
        if (!found_any) {
            printf("[master] Not found – queued for retry when servants update.\n");
            if (n_retry >= cap_retry) {
                cap_retry = cap_retry ? cap_retry*2 : 64;
                retry = (uint64_t*)realloc(retry, cap_retry*sizeof(uint64_t));
            }
            retry[n_retry++] = qhash;
        }
        fflush(stdout);
    }

    /* stop servants */
    uint8_t stop = 0;
    for (int r = 1; r <= nservants; r++)
        MPI_Send(&stop, 1, MPI_BYTE, r, TAG_STOP, MPI_COMM_WORLD);

    for (int r = 1; r <= nservants; r++) if (servant_bf[r]) bloom_free(servant_bf[r]);
    free(servant_bf); free(retry);
    printf("[master] done.\n");
}

/* ── servant ── */
static void servant(int rank) {
    /* receive assignment */
    MPI_Status status;
    MPI_Probe(0, TAG_ASSIGN, MPI_COMM_WORLD, &status);
    int bufsz; MPI_Get_count(&status, MPI_BYTE, &bufsz);
    uint8_t *buf = (uint8_t*)malloc(bufsz);
    MPI_Recv(buf, bufsz, MPI_BYTE, 0, TAG_ASSIGN, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

    int off = 0;
    uint64_t start, count, bloom_bits, report_interval;
    int clen, pwlen;
    char charset[MAX_CSET+1];
    memcpy(&start,&buf[off],8);           off+=8;
    memcpy(&count,&buf[off],8);           off+=8;
    memcpy(&bloom_bits,&buf[off],8);      off+=8;
    memcpy(&report_interval,&buf[off],8); off+=8;
    memcpy(&clen,&buf[off],4);            off+=4;
    memcpy(&pwlen,&buf[off],4);           off+=4;
    memcpy(charset,&buf[off],clen+1);
    free(buf);

    printf("[servant %d] range [%llu, %llu)  pwlen=%d charset_len=%d\n",
           rank,(unsigned long long)start,(unsigned long long)(start+count),pwlen,clen);
    fflush(stdout);

    BloomFilter *bf = bloom_create(bloom_bits ? bloom_bits : count*10+1024, 7);

    /* local hash table: open addressing, uint64 key */
    uint32_t ht_cap  = LOCAL_TABLE_MAX;
    TableEntry *ht   = (TableEntry *)calloc(ht_cap, sizeof(TableEntry));
    uint32_t    ht_sz = 0;
    /* sentinel: hash==0 means empty (we skip inserting hash=0) */
    #define HT_MASK (ht_cap - 1)

    uint64_t next_report = report_interval;

    for (uint64_t i = 0; i < count; i++) {
        /* check for stop or query messages */
        if (i % 65536 == 0) {
            int flag;
            MPI_Iprobe(0, TAG_STOP, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
            if (flag) goto done;

            MPI_Iprobe(0, TAG_QUERY, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
            if (flag) {
                uint64_t qhash;
                MPI_Recv(&qhash, sizeof(qhash), MPI_BYTE, 0, TAG_QUERY,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                uint8_t resp[1+MAX_PW_LEN+1];
                resp[0] = 0;
                /* look up in hash table */
                if (qhash != 0) {
                    uint32_t slot = (uint32_t)(qhash & HT_MASK);
                    for (uint32_t k=0; k<ht_cap; k++) {
                        if (ht[slot].hash == 0) break;
                        if (ht[slot].hash == qhash) {
                            resp[0] = 1;
                            memcpy(resp+1, ht[slot].pw, pwlen+1);
                            break;
                        }
                        slot = (slot+1) & HT_MASK;
                    }
                }
                MPI_Send(resp, sizeof(resp), MPI_BYTE, 0, TAG_RESP, MPI_COMM_WORLD);
            }
        }

        /* compute candidate and hash */
        char pw[MAX_PW_LEN+1];
        idx_to_pw(start+i, charset, clen, pwlen, pw);
        uint64_t h = xxh64((const uint8_t*)pw, (size_t)pwlen, 0);

        /* bloom filter */
        bloom_add(bf, &h, sizeof(h));

        /* local table (if space and h != 0) */
        if (h != 0 && ht_sz < ht_cap * 3 / 4) {
            uint32_t slot = (uint32_t)(h & HT_MASK);
            for (uint32_t k=0; k<64; k++) {
                if (ht[slot].hash == 0) {
                    ht[slot].hash = h;
                    memcpy(ht[slot].pw, pw, pwlen+1);
                    ht_sz++;
                    break;
                }
                if (ht[slot].hash == h) break; /* dup */
                slot = (slot+1) & HT_MASK;
            }
        }

        /* periodic bloom report to master */
        if (i+1 == next_report || i+1 == count) {
            size_t bsz = bloom_serial_size(bf);
            uint8_t *bbuf = (uint8_t*)malloc(bsz);
            bloom_serialise(bf, bbuf);
            MPI_Send(bbuf, (int)bsz, MPI_BYTE, 0, TAG_BLOOM, MPI_COMM_WORLD);
            free(bbuf);
            printf("[servant %d] bloom report sent (%llu hashes computed)\n",
                   rank, (unsigned long long)(i+1));
            fflush(stdout);
            next_report += report_interval;
        }
    }

done:
    /* drain any remaining query before exiting */
    {
        int flag;
        do {
            MPI_Iprobe(0, TAG_QUERY, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
            if (flag) {
                uint64_t qhash;
                MPI_Recv(&qhash, sizeof(qhash), MPI_BYTE, 0, TAG_QUERY,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                uint8_t resp[1+MAX_PW_LEN+1]; resp[0]=0;
                if (qhash != 0) {
                    uint32_t slot = (uint32_t)(qhash & HT_MASK);
                    for (uint32_t k=0; k<ht_cap; k++) {
                        if (ht[slot].hash == 0) break;
                        if (ht[slot].hash == qhash) { resp[0]=1; memcpy(resp+1,ht[slot].pw,pwlen+1); break; }
                        slot=(slot+1)&HT_MASK;
                    }
                }
                MPI_Send(resp, sizeof(resp), MPI_BYTE, 0, TAG_RESP, MPI_COMM_WORLD);
            }
        } while (flag);
    }
    printf("[servant %d] done.\n", rank); fflush(stdout);
    free(ht); bloom_free(bf);
}

/* ── main  */
int main(int argc, char **argv) {
    MPI_Init(&argc, &argv);
    int rank, nprocs;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

    if (argc < 3) {
        if (rank==0) fprintf(stderr,
            "usage: mpirun -np N %s <charset> <pwlen> [bloom_bits] [report_interval]\n",argv[0]);
        MPI_Finalize(); return 1;
    }
    const char *charset = argv[1];
    int pwlen = atoi(argv[2]);
    uint64_t bloom_bits       = (argc>3) ? (uint64_t)strtoull(argv[3],NULL,10) : 0;
    uint64_t report_interval  = (argc>4) ? (uint64_t)strtoull(argv[4],NULL,10) : 1000000ULL;

    if (strlen(charset) > MAX_CSET || pwlen < 1 || pwlen > MAX_PW_LEN) {
        if (rank==0) fprintf(stderr,"charset max %d, pwlen max %d\n",MAX_CSET,MAX_PW_LEN);
        MPI_Finalize(); return 1;
    }

    if (rank == 0) master(nprocs, charset, pwlen, bloom_bits, report_interval);
    else           servant(rank);

    MPI_Finalize();
    return 0;
}
