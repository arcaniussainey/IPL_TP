#ifndef MD5_HELPERS
#define MD5_HELPERS
// MD5 RFC impls of helpers

#include "md5.h"
#define MD 5

/* Length of test block, number of test blocks.
 */
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000

void MDString(char *);
static void MDTimeTrial(void);
static void MDTestSuite(void);
void MDFile(char *);
void MDFilter(void);
void MDPrint(unsigned char [16]);

#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final
#endif