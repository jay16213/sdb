#ifndef __DEBUG_H__
#define __DEBUG_H__

#ifdef DEBUG
#include "stdio.h"
#define d_trace(fmt, ...) {fprintf(stderr, "\033[33m[DEBUG](%s:%u) " fmt "\033[0m\n", __FILE__, __LINE__, ## __VA_ARGS__); fflush(stderr);}
#else
#define d_trace(fmt, ...) ;
#endif

#endif
