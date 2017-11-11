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


static int binder_update_page_range(struct binder_alloc *alloc, int allocate,
							void *start, void *end,
							struct vm_area_struct *vma)
{
	void *page_addr;
	unsigned long user_page_addr;
	struct binder_lru_page *page;
	struct mm_struct *mm = NULL;
	bool need_mm = false;
	
	binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
		"%d:%s pages %pK-%pK\n", alloc->pid,
		alllcate ? "allocate" : "free", start, end);
	if(end <= start)
		return 0;
	
	trace_binder_update_page_range(alloc, allocate, start, end);
	
	if(allocate == 0)
		goto free_range;
	
	for(page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
		page = &alloc->pages[(page_addr - alloc->buffer)/ PAGE_SIZE];
		if(!page->page_ptr) {
			need_mm = true;
			break;
		}
	}
	if(!vma && need_mm)
		mm = get_task_mm(alloc->tsk);
	
	if(mm) {
		down_write(&mm->mmap_sem);
		vma = alloc->vma;
		if(vma && mm != alloc->vma_vm_mm) {
			pr_err("%d:vma mm and task mm mismatch\n",
				alloc->pid);
			vma = NULL;
		}
	}
	
	if(!vma && need_mm) {
		pr_err("%d: binder_alloc_buf failed to map pages in userspace, no vma\n",
			alloc->pid);
		goto err_no_vma;
	}
	
	for(page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
		int ret;
		bool on_lru;
		size_t index;
		
		index = (page_addr - alloc->buffer) / PAGE_SIZE;
		page = &alloc->pages[index];
		
		if(page->page_ptr) {
			trace_binder_alloc_lru_start(alloc, index);
			
			on_lru = list_lru_del(&binder_alloc_lru, &page->lru);
			WARN_ON(!on_lru);
			
			trace_binder_alloc_lru_end(alloc, index);
			continue;
		}
		if(WARN_ON(!vma))
			goto err_page_ptr_cleared;
		
		trace_binder_alloc_page_start(alloc, index);
		page->page_ptr = alloc_page(GFP_KERNEL |	
					__GFP_HIGHMEM |
					__GFP_ZERO);
		if(!page->page_ptr) {
			pr_err("%d:binder_alloc_buf failed for page  at %pK\n",
				alloc->pid, page_addr);
			goto err_alloc_page_failed;
		}
		page->alloc = alloc;
		INIT_LIST_HEAD(&page->lru);
		
		ret = map_kernel_range_noflush((unsigned long)page_addr,
					PAGE_SIZE, PAGE_KERNEL,
					&page->page_ptr);
		flush_cache_vmap((unsigned long)page_addr,
				(unsigned long)page_addr + PAGE_SIZE);
		if(ret != 1) {
			pr_err("%d: binder_alloc_buf failed to map page at %pK in kernel\n",
				alloc->pid, page_addr);
			goto  err_map_kernel_failed;
		}
		
		user_page_addr = 
			(uintptr_t)page_addr + alloc->user_buffer_offset;
		ret = vm_insert_page(vma, user_page_addr, page[0].page_ptr);
		if(ret) {
			pr_err("%d: binder_alloc_buf failed to map page at %lx in userspace\n",
				alloc->pid, user_page_addr);
			goto err_vm_insert_page_failed;
		}
		trace_binder_alloc_page_end(alloc, index);
		/** vm_insert_page does not seem to increment the refcount */
		
	}
	if(mm){
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return 0;
free_range:
	for(page_addr = end - PAGE_SIZE; page_addr >= start;
			page_addr -= PAGE_SIZE){
		bool ret;
		size_t index;
		
		index = (page_addr - alloc->buffer)/ PAGE_SIZE;
		page = &alloc->pages[index];
		
		trace_binder_free_lru_start(alloc, index);
		
		ret = list_lru_add(&binder_alloc_lru, &page->lru);
		WARN_ON(!ret);
		
		trace_binder_free_lru_end(alloc, index);
		continue;
err_vm_insert_page_failed:
		unmap_kernel_range((unsigned long)page_ptr, PAGE_SIZE);
err_map_kernel_failed:
		__free_page(page->page_ptr);
		page->page_ptr = NULL;
err_alloc_page_failed:
err_page_ptr_cleared:
		
	}
err_no_vma:
	if(mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return vma ? -ENOMEM : -ESRCH;
}

struct binder_buffer *binder_alloc_new_buf_locked(struct binder_alloc *alloc,
						size_t data_size,
						size_t offsets_size,
						size_t extra_buffers_size,
						int is_async)
{
	struct rb_node *n = alloc->free_buffers.rb_node;
	struct binder_buffer *buffer;
	size_t buffer_size;
	struct rb_node *best_fit = NULL;
	void *has_page_addr;
	void *end_page_addr;
	size_t size, data_offsets_size;
	int ret;
	
	if(alloc->vma == NULL) {
		pr_err("%d: binder_alloc_buf, no vma\n",
			alloc->pid);
		return ERR_PTR(-ESRCH);
	}
	
	data_offsets_size = ALGIN(data_size , sizeof(void *)) + 
				ALGIN(offsets_size, sizeof(void *));
	
	if(data_offsets_size < data_size || data_offsets_size < offsets_size) {
		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
			"%d: got transaction with invalid size %zd-%zd\n",
			alloc->pid, data_size, offsets_size);
		return ERR_PTR(-EINVAL);
	}
	size = data_offsets_size + ALIGN(extra_buffers_size, sizeof(void *));
	if(size  < data_offsets_size || size < extra_buffers_size) {
		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
			"%d: got transaction with invalid extra_buffers_size %zd\n",
			alloc->pid, extra_buffers_size);
		return ERR_PTR(-EINVAL);
	}
	if(is_async &&
		alloc->free_async_space < size + sizeof(struct binder_buffer)) {
		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
			"%d: binder_alloc_buf size %zd failed, no async space left\n",
			alloc->pid, size);
		return ERR_PTR(-ENOSPC);
	}
	/** Pad 0-size buffers so they get assigned unique addresses **/
	size = max(size, sizeof(void *));
	
	while(n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		buffer_size = binder_alloc_buffer_size(alloc, buffer);
		
		if(size < buffer_size) {
			best_fit = n;
			n = n->rb_left;
			
		}
		else if(size > buffer_size) {
			n = n->rb_right;
		} 
		else {
			best_fit = n;
			break;
		}
	}
	if(best_fit == NULL) {
		size_t allocated_buffers = 0;
		size_t largest_alloc_size = 0;
		size_t total_alloc_size = 0;
		size_t free_buffers = 0;
		size_t largest_free_size = 0;
		size_t total_free_size = 0;
		
		for(n = rb_first(&alloc->allocated_buffers; n != NULL;
			n = rb_next(n)) {
			buffer = rb_entry(n, struct binder_buffer , rb_node);
			buffer_size = binder_alloc_buffer_size(alloc, buffer);
			allocated_buffers++;
			total_alloc_size += buffer_size;
			if(buffer_size > largest_alloc_size)
				largest_alloc_size = buffer_size;
		}
		
		for(n = rb_first(&alloc->free_buffers); n != NULL;
			n = rb_next(n)) {
			buffer = rb_entry(n, struct binder_buffer, rb_node);
			buffer_size = binder_alloc_buffer_size(alloc, buffer);
			free_buffers++;
			total_free_size += buffer_size;
			if(buffer_size > largest_free_size)
				largest_free_size = buffer_size;
		}
		pr_err("%d: binder_alloc_buf size %z failed, no addresses space\n",
			alloc->pid, size);
		pr_err("allocated: %zd (num:%zd largest:%zd),free:%zd(num:%zd largest: %zd)\n",
			total_alloc_size, allocated_buffers, largest_alloc_size,
			total_free_size, free_buffers,largest_free_size);
		return ERR_PTR(-ENOSPC);
	}
	
	if(n == NULL) {
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		buffer_size = binder_alloc_buffer_size(alloc, buffer);
	}
	
	binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
		"%d: binder_alloc_buf size %zd got buffer %pK size %zd\n",
		alloc->pid, size, buffer, buffer_size);
	has_page_addr = 
		(void *)(((uintptr_t) buffer->data + buffer_size) & PAGE_MASK);
	WARN_ON(n && buffer_size != size);
	end_page_addr = (void *) PAGE_ALIGN((uintptr_t)buffer->data + size);
	if(end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;
	ret = binder_update_page_range(alloc,1,
			(void *)PAGE_ALIGN((uintptr_t) buffer->data),end_page_addr, NULL);
	if(ret)
		return ERR_PTR(ret);
	
	if(buffer_size != size) {
		struct binder_buffer *new_buffer;
		
		new_buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
		if(!new_buffer) {
			pr_err("%s:%d failed to alloc new buffer struct\n",
				__func__, alloc->pid);
			goto err_alloc_buf_struct_failed;
		}
		new_buffer->data = (u8 *)buffer->data + size;
		list_add(&new_buffer->entry, &buffer->entry);
		new_buffer->free = 1;
		binder_insert_free_buffer(alloc, new_buffer);
		
	}
	rb_erase(best_fit, &alloc->free_buffers);
	buffer->free = 0;
	buffer->free_in_progress = 0;
	binder_insert_allocated_buffer_locked(alloc, buffer);
	binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC,
		"%d: binder_alloc_buf size %zd got %pK\n",
		alloc->pid, size, buffer);
	buffer->data_size = data_size;
	buffer->offsets_size = offsets_size;
	buffer->async_transaction = is_async;
	buffer->extra_buffers_size = extra_buffers_size;
	if(is_async) {
		alloc->free_async_space -= size + sizeof(struct binder_buffer);
		binder_alloc_debug(BINDER_DEBUG_BUFFER_ALLOC_ASYNC,
			"%d: binder_alloc_buf size %zd async free %zd\n",
			alloc->pid, size, alloc->free_async_space);
	}
	return buffer;
err_alloc_buf_struct_failed:
	binder_update_page_range(alloc, 0,
		(void *)PAGE_ALIGN((uintptr_t)buffer->data),
		end_page_addr, NULL);
	return ERR_PTR(-ENOMEM);
}


/**
** binder_alloc_new_buf() - Allocate a new binder buffer
** @alloc:     binder_alloc for this proc
** @data_size : size of user data buffer
** @offsets_size： user specified buffer offset
** @extra_buffers_size:  size of extra space for meta-data(eg, security context)
** @is_async:  buffer for async transaction
**
** Allocate a new buffer given the requested sizes, Returns
** the kernel version of the buffer pointer. The size allocated
** is the sum of the three given sizes(each rounded up to 
** pointer-sized boundary)
**
** Return: The allocated buffer or %NULL if error
**/
struct binder_buffer *binder_alloc_new_buf(struct binder_alloc *alloc,
							size_t data_size,
							size_t offsets_size,
							size_t extra_buffers_size,
							int is_async)
{
	struct binder_buffer *buffer;
	
	mutex_lock(&alloc->mutex);
	buffer = binder_alloc_new_buf_locked(alloc, data_size, offsets_size,
					extra_buffers_size, is_async);
	mutex_unlock(&alloc->mutex);
	return buffer;
}

static void *buffer_start_page(struct binder_buffer *buffer)
{
	return (void *)((uintptr_t)buffer->data & PAGE_MASK);
}

static void *prev_buffer_end_page(struct binder_buffer *buffer)
{
	return (void *)(((uintptr_t)(buffer->data) - 1) & PAGE_MASK);
}




















































