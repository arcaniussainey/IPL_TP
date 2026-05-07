#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifndef ARRAY_LEN
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#endif

#endif
