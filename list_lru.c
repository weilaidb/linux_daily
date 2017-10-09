/**
**
** Generic LRU infrastructure
**/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/list_lru.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/memcontrol.h>

#if defined(CONFIG_MEMCG) && !defined(CONFIG_SLOB)
static LIST_HEAD(list_lrus);
static DEFINE_MUTE(list_lrus_mutex);

static void list_lru_register(struct list_lru *lru)
{
	mutex_lock(&list_lrus_mutex);
	list_add(&lru->list, &list_lrus);
	mutex_unlock(&list_lrus_mutex);
}

static void list_lru_unregister(struct list_lru *lru)
{
	mutex_lock(&list_lrus_mutex);
	list_del(&lru->list);
	mutex_unlock(&list_lrus_mutex);
}

#else
static void list_lru_register(struct list_lru *lru)
{
	
}

static void list_lru_unregister(struct list_lru *lru)
{
	
}

#endif /** CONFIG_MEMCG && ! CONFIG_SLOB **/

#if defined(CONFIG_MEMCG) && !defined(CONFIG_SLOB)
static inline bool list_lru_memcg_aware(struct list_lru *lru)
{
	/**
	** This needs node 0 to be always present, even
	** in the systems supporting sparse numa ids.
	**/
	return !! lru->node[0].memcg_lrus.
}

static inline struct list_lru_one *
	list_lru_from_memcg_idx(struct list_lru_node *nlru, int idx)
{
	/**
	** The lock protects the array of per cgroup lists from relocation
	** (see memcg_update_list_lru_node).
	**/
	lockdep_assert_held(&nlru->lock);
	if(nlru->memcg_lrus && idx >= 0)
		return nlru->memcg_lrus->lru[idx];
	return &nlru->lru;
}

static __always_inline struct mem_cgroup *mem_cgroup_from_kmem(void *ptr)
{
	struct page *page;
	
	if(!memcg_kmem_enabled())
		return NULL;
	
	page = virt_to_head_page(ptr);
	return page->mem_cgroup;
}

static inline struct list_lru_one *
list_lru_from_kmem(struct list_lru_node *nlru, void *ptr)
{
	struct mem_cgroup *memcg;
	
	if(!nlru->memcg_lrus)
		return &nlru->lru;
	memcg = mem_cgroup_from_kmem(ptr);
	if(!memcg)
		return &nlru->lru;
	
	return list_lru_from_memcg_idx(nlru, memcg_cache_id(memcg));
}
#else
static inline bool list_lru_memcg_aware(struct list_lru *lru)
{
	return false;
}

static inline struct list_lru_one *
list_lru_from_memcg_idx(struct list_lru_node *nlru, int idx)
{
	return &nlru->lru;
}

static inline struct list_lru_one *
list_lru_from_kmem(struct list_lru_node *nlru, void *ptr)
{
	return &nlru->lru;
}
#endif /** CONFIG_MEMCG && !CONFIG_SLOB **/

bool list_lru_add(struct list_lru *lru, struct list_head *item)
{
	int nid = page_to_nid(virt_to_page(item));
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;
	
	spin_lock(&nlru->lock);
	if(list_empty(item)) {
		l= list_lru_from_kmem(nlru, item);
		list_add_tail(item, &l->list);
		l->nr_items++;
		nlru->nr_items++;
		spin_unlock(&nlru->lock);
		return true;
	}	
	spin_unlock(&nlru->lock);
	return false;
}
EXPORT_SYMBOL(list_lru_add);

bool list_lru_del(struct list_lru *lru, struct list_head *item)
{
	int nid = page_to_nid(virt_to_page(item));
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;
	
	spin_lock(&nlru->lock);
	if(!list_empty(item)) {
		l = list_lru_from_kmem(nlru, item);
		list_del_init(item);
		l->nr_items--;
		nlru->nr_items--;
		spin_unlock(&nlru->lock);
		return true;
	}
	spin_unlock(&nlru->lock);
	return false;
}
EXPORT_SYMBOL_GPL(list_lru_del);

void list_lru_isolate(struct list_lru_one *list, struct list_head *item)
{
	list_del_init(item);
	list->nr_items--;
}
EXPORT_SYMBOL_GPL(list_lru_isolate);


void list_lru_isolate_move(struct list_lru_one *list, struct list_head *item,
				struct list_head *head)
{
	list_move(item, head);
	list->nr_items--;
}
EXPORT_SYMBOL_GPL(list_lru_isolate_move);

static unsigned long __list_lru_count_one(struct list_lru *lru,
							int nid, int memcg_idx)
{
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;
	unsigned long count;
	
	spin_lock(&nlru->lock);
	l = list_lru_from_memcg_idx(nlru, memcg_idx);
	count = l->nr_items;
	spin_unlock(&nlru->lock);
	
	return count;
}

unsigned long list_lru_count_one(struct list_lru *lru,
			int nid, struct mem_cgroup *memcg)
{
	return __list_lru_count_one(lru, nid, memcg_cache_id(memcg));
}
EXPORT_SYMBOL_GPL(list_lru_count_one);

unsigned long list_lru_count_node(struct list_lru *lru, int nid)
{
	struct list_lru_node *nlru;
	
	nlru = &lru->node[nid];
	return nlru->nr_items;
}
EXPORT_SYMBOL_GPL(list_lru_count_node);

static unsigned long 
__list_lru_walk_one(struct list_lru *lru, int nid, int memcg_idx,
				list_lru_walk_cb isolate, void *cb_arg,
				unsigned long *nr_to_walk)
{
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;
	struct list_head *item, *n;
	unsigned long isolated = 0;
	
	spin_lock(&nlru->lock);
	l = list_lru_from_memcg_idx(nlru, memcg_idx);
restart:
	list_for_each_safe(item, n, &l->list) {
		enum lru_status ret;
		
		/**
		** decrement nr_to_walk first so that we don't livelock if we 
		** get stuck on large numbers of LRU_RETRY items
		**/
		if(!*nr_to_walk) 
			break;
		-- *nr_to_walk;
		
		ret = isolate(item, l, &nlru->lock, cb_arg);
		switch(ret) {
		case LRU_REMOVED_RETRY:
			assert_spin_locked(&nlru->lock);
		case LRU_REMOVED:
			isolated++;
			nlru->nr_items--;
			/**
			** If the lock has been dropped, our list 
			** traversal is now invalid and so we have to 
			** restart from scratch.
			**/
			if(ret == LRU_REMOVED_RETRY)
				goto restart;
			break;
		case LRU_ROTATE:
			list_move_tail(item, &l->list);
			break;
		case LRU_SKIP:
			break;
		case LRU_RETRY:
			/**
			** The lru lock has been dropped, our list traversal is 
			** now invalid and so we have to restart from scratch.
			**/
			assert_spin_locked(&nlru->lock);
			goto restart;
		default:
			BUG();
		}
	}
	
	spin_unlock(&nlru->lock);
	return isolated;
}


































































































































































