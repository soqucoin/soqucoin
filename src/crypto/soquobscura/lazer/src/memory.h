#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

static void *alloc_default (size_t)
    __attribute__ ((__returns_nonnull__, alloc_size (1)));
static void *realloc_default (void *, size_t, size_t)
    __attribute__ ((__returns_nonnull__, alloc_size (2)));
static void free_default (void *, size_t);

static void *(*_alloc) (size_t) = alloc_default;
static void *(*_realloc) (void *, size_t, size_t) = realloc_default;
static void (*_free) (void *, size_t) = free_default;

#endif
