/**
** binder_alloc.c
** Android IPC Subsystem
**
****
**/
#include <asm/cacheflush.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/rtmutex.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/list_lru.h>
#include "binder_alloc.h"
#include "binder_trace.h"

struct list_lru binder_alloc_lru;

static DEFINE_MUTEX(binder_alloc_mmap_lock);

enum {
	BINDER_DEBUG_OPEN_CLOSE  = 1U << 1，
	BINDER_DEBUG_BUFFER_ALLOC  = 1U << 2,
	BINDER_DEBUG_BUFFER_ALLOC_ASYNC = 1U << 3,
};

static uint32_t binder_alloc_debug_mask;

module_param_named(debug_mask, binder_alloc_debug_mask,
	uint, 0644);

#define binder_alloc_debug(mask, x...)\
	do{\
		if(binder_alloc_debug_mask &mask)\
			pr_info(x);\
	}while(0)
		
static struct binder_buffer *binder_buffer_next(struct binder_buffer *buffer)
{
	return list_entry(buffer->entry.next, struct binder_buffer, entry);
}

static struct binder_buffer *binder_buffer_prev(struct binder_buffer *buffer)
{
	return list_entry(buffer->entry.prev, struct binder_buffer, entry);
}

static size_t binder_alloc_buffer_size(struct binder_alloc *alloc,
						struct binder_buffer *buffer)
{
	if(list_is_last(&buffer->entry, &alloc->buffers))
		return (u8 *)alloc->buffer +
				alloc->buffer_size - (u8 *)buffer->data;
	return (u8 *)binder_buffer_next(buffer)->data - (u8 *)buffer->data;
}
























































