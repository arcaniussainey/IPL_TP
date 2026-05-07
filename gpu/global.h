/* GLOBAL.H - RSAREF types and constants
 */
#include <stdint.h>

#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

typedef uint8_t *POINTER;
typedef uint16_t UINT2;
typedef uint32_t UINT4;

#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif
