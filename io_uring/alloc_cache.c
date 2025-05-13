// SPDX-License-Identifier: GPL-2.0

#include "alloc_cache.h"

/*
 * io_alloc_cache_free - Free all cached entries in an io_alloc_cache
 *
 * @cache: Pointer to the cache structure to free
 * @free: Callback function used to deallocate each individual entry
 *
 * This function removes and frees all entries stored in the cache,
 * then deallocates the internal array used to hold the cached pointers.
 */
void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *))
{
	void *entry;

	if (!cache->entries)
		return;

	while ((entry = io_alloc_cache_get(cache)) != NULL)
		free(entry);

	kvfree(cache->entries);
	cache->entries = NULL;
}

/*
 * io_alloc_cache_init - Initialize an io_alloc_cache structure
 *
 * @cache: Pointer to the cache structure to initialize
 * @max_nr: Maximum number of elements the cache can hold
 * @size: Size of each element
 * @init_bytes: Number of bytes to zero out upon allocation
 *
 * Returns false (0) on successful initialization, or true (non-zero)
 * if allocation of the internal array fails.
 */
/* returns false if the cache was initialized properly */
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes)
{
	cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);
	if (!cache->entries)
		return true;

	cache->nr_cached = 0;
	cache->max_cached = max_nr;
	cache->elem_size = size;
	cache->init_clear = init_bytes;
	return false;
}

/*
 * io_cache_alloc_new - Allocate a new object for the io_alloc_cache
 
 * @cache: Pointer to the cache structure
 * @gfp: GFP flags for memory allocation
 *
 * Allocates a new memory object of size cache->elem_size.
 * If init_clear is set, the object is zero-initialized for the
 * first init_clear bytes.
 *
 * Returns a pointer to the newly allocated object, or NULL on failure.
 */
 
void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = kmalloc(cache->elem_size, gfp);
	if (obj && cache->init_clear)
		memset(obj, 0, cache->init_clear);
	return obj;
}
