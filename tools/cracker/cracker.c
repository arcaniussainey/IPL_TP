#include "md5.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cheap hex conversion
static int hex_value(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// validate that a string is md5, and has a value to compute
static int parse_md5_hex(const char *hex, unsigned char digest[16])
{
    if (strlen(hex) != 32)
        return 0;

    for (int i = 0; i < 16; i++)
    {
        int hi = hex_value((unsigned char)hex[i * 2]);
        int lo = hex_value((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        digest[i] = (unsigned char)((hi << 4) | lo);
    }

    return 1;
}

static void md5_bytes(char *string, unsigned int len, unsigned char digest[16])
{
    MD5_CTX context;

    MD5Init(&context);
    MD5Update(&context, (unsigned char *)string, len);
    MD5Final(digest, &context);
}

static int test_candidate(char *candidate, unsigned int len,
                          const unsigned char target[16])
{
    unsigned char digest[16];
    md5_bytes(candidate, len, digest);
    return memcmp(digest, target, 16) == 0;
}

static int crack_length(const unsigned char target[16], const char *charset,
                        size_t charset_len, unsigned int len, char *candidate,
                        size_t *indexes)
{
    memset(indexes, 0, len * sizeof(*indexes));
    memset(candidate, charset[0], len);
    candidate[len] = '\0';

    for (;;)
    {
        if (test_candidate(candidate, len, target))
        {
            printf("Password found: %s\n", candidate);
            return 1;
        }

        unsigned int pos = len;
        while (pos > 0)
        {
            pos--;
            indexes[pos]++;
            if (indexes[pos] < charset_len)
            {
                candidate[pos] = charset[indexes[pos]];
                break;
            }
            indexes[pos] = 0;
            candidate[pos] = charset[0];
        }

        if (pos == 0 && indexes[0] == 0)
            return 0;
    }
}

// brute-force an md5 hash with a provided charset up to a maximum length
int main(int argc, char **argv)
{
    unsigned char target[16];
    char *end = NULL;
    unsigned long max_len;
    const char *charset;
    size_t charset_len;
    char *candidate;
    size_t *indexes;

    if (argc != 4) // validate args
    {
        fprintf(stderr, "usage: %s <md5_hex> <charset> <max_length>\n", argv[0]);
        return 2;
    }

    if (!parse_md5_hex(argv[1], target))
    {
        fprintf(stderr, "invalid md5 hex digest\n");
        return 2;
    }

    charset = argv[2];
    charset_len = strlen(charset); // formally, doesn't elim repeats
    if (charset_len == 0)
    {
        fprintf(stderr, "charset must not be empty\n");
        return 2;
    }

    errno = 0;
    max_len = strtoul(argv[3], &end, 10);
    if (errno || *end != '\0' || max_len == 0 || max_len > UINT_MAX) //validate passlen, ensure that any error isn't caused by invalid systsem/arg state in main
    {
        fprintf(stderr, "max_length must be a positive integer\n");
        return 2;
    }

    candidate = malloc(max_len + 1);
    if (!candidate)
    {
        fprintf(stderr, "failed to allocate candidate buffer\n");
        return 1;
    }

    indexes = malloc(max_len * sizeof(*indexes));
    if (!indexes)
    {
        free(candidate);
        fprintf(stderr, "failed to allocate search buffer\n");
        return 1;
    }

    for (unsigned int len = 1; len <= (unsigned int)max_len; len++)
    {
        if (crack_length(target, charset, charset_len, len, candidate, indexes))
        {
            free(indexes);
            free(candidate);
            return 0;
        }
    }

    free(indexes);
    free(candidate);
    printf("Password not found\n");
    return 1;
}
