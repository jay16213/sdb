#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdio.h>

#define SDB_INFO(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define SDB_ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#endif
