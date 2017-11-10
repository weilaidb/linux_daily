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

static void binder_insert_free_buffer(struct binder_alloc *alloc,
				struct binder_buffer *new_buffer)
{
	struct rb_node **p = &alloc->free_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;
	size_t buffer_size;
	size_t new_buffer_size;
	
	BUG_ON(!new_buffer->free);
	
	new_buffer_size = binder_alloc_buffer_size(alloc, new_buffer);
	
	binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
		"%d: add free buffer, size %zd, at %pK\n",
		alloc->pid, new_buffer_size, new_buffer);
	
	while(*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		
		buffer_size = binder_alloc_buffer_size(alloc, buffer);
		if(new_buffer_size < buffer_size)
			p = &parent->rb_left;
		else 
			p = &parent->rb_right;
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &alloc->free_buffers);
	
}

static void binder_insert_allocated_buffer_locked(
				struct binder_alloc *alloc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &alloc->allocated_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;
	
	BUG_ON(new_buffer->free);
	
	while(*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);
		
		if(new_buffer->data < buffer->data)
			p = &parent->rb_left;
		else if(new_buffer->data > buffer->data)
			p = &parent->rb_right;
		else
			BUG();
			
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &alloc->allocated_buffers);
}

static struct binder_buffer *binder_alloc_prepare_to_free_locked(
				struct binder_alloc *alloc,
				uintptr_t user_ptr)
{
	struct rb_node *n = alloc->allocated_buffers.rb_node;
	struct binder_buffer *buffer;
	void *kern_ptr;
	
	kern_ptr = (void *)(user_ptr - alloc->user_buffer_offset);
	
	while(n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);
		
		if(kern_ptr < buffer->data)
			n = n->rb_left;
		else if (kern_ptr > buffer->data)
			n = n->rb_right;
		else {
			/**
			** Guard against user threads attempting to 
			** free the buffer twice
			**/
			if(buffer->free_in_progress) {
				pr_err("%d:%d FREE_BUFFER u%016llx user freed buffer twice\n",
				alloc->pid, current->pid,(u64)user_ptr);
				return NULL;
			}
			buffer->free_in_progress = 1;
			return buffer;
		}
	}
	return NULL;
}

/**
** binder_alloc_buffer_lookup() - get buffer given user ptr 
** @alloc:  binder_alloc for this proc
** @user_ptr: User pointer to buffer data 
**
** Validate userspace pointer to buffer data and return buffer corresponding to 
** that user pointer. Search the rb tree for buffer that matchess user data pointer.
**
** Return: Pointer to buffer or NULL
**/
struct binder_buffer * binder_alloc_prepare_to_free(struct binder_alloc *alloc,
							uintptr_t user_ptr)
{
	struct binder_buffer *buffer;
	
	mutex_lock(&alloc->mutex);
	buffer = binder_alloc_prepare_to_free_locked(alloc, user_ptr);
	mutex_unlock(&alloc->mutex);
	return buffer;
}























































