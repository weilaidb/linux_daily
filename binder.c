/**
 binder.c
 **/
 
/**
** Locking overview 
** 
** There are 3 main spinlocks which must be accuquired in the 
** order shown:
**
** 1) proc->outer_lock: protects binder_ref 
**     binder_proc_lock() and binder_proc_unlock() are 
**     used to acq/rel
** 2)node->lock: protects most fields of binder_node.
**           binder_node_lock() and binder_node_unlock()
**           used to acq/rel.
** 3)proc->inner_lock: protects the thread and node lists
**    (proc->threads, proc->waiting_threads,proc->nodes)
**    and all todo lists associated with the binder_proc 
** (proc->todo, thread->todo, proc->delivered_death and 
** node->async_todo), as well as thread->transaction_stack
** binder_inner_proc_lock() and binder_inner_proc_unlock() 
** are used to acq/rel.

** 
** Any lock under procA must never be nested under any lock at the same level or below on procB.
**
** Functions that require a lock held on entry indicate which lock 
** in the suffix of the function name:
**
** foo_olocked(): requires node->outer_lock
** foo_nlocked(): requires node->lock
** foo_ilocked(): requires proc->inner_lock
** foo_oilocked(): requires proc->outer_lock and proc->inner_lock
** foo_nilocked(): requires node->lock and proc->inner_lock
**...
**/

#define pr_fmt(fmt) KBUILD_MODNAME ":"fmt

#include <asm/cacheflush.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/debugfs.h>
#include <linux/rbtree.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/spinlock.h>

#ifdef CONFIG_ANDROID_BINDER_IPC_32BIT
#define BINDER_IPC_32BIT 1
#endif

#include <uapi/linux/android/binder.h>
#include "binder_alloc.h"
#include "binder_trace.h"

static HLIST_HEAD(binder_deferred_list);
static DEFINE_MUTEX(binder_deferred_list);

static HLIST_HEAD(binder_devices);
static HLIST_HEAD(binder_procs);
static DEFINE_MUTEX(binder_procs_lock);

static HLIST_HEAD(binder_dead_nodes);
static DEFINE_SPINLOCK(binder_dead_nodes_lock);

static struct dentry * binder_debuffs_dir_entry_root;
static struct dentry *binder_debugfs_dir_entry_proc;
static atomic_t binder_last_id;

#define BINDER_DEBUG_ENTRY(name) \
static int binder_##name##_open(struct inode *inode, struct file *file)\
{\
	return single_open(file, binder_##name##_show, inode->i_private);\
}\
\
static const struct file_operations binder_##name##_fops = {\
	.owner = THIS_MODULE, \
	.open  = binder_##name##_open,\
	.read  = seq_read;\
	.llseek = seq_lseek;\
	.release = single_release,\
}

static int binder_proc_show(struct seq_file *m, void * unused);
BINDER_DEBUG_ENTRY(proc);

/** This is only defined in include/asm-arm/ sizes.h **/
#ifndef SZ_1K 
#define SZ_1K  0x400
#endif

#ifndef SZ_4M
#define SZ_4M  0x400000
#endif

#define FORBINDDEN_MMAP_FLAGS (VM_WRITE)

enum {
	BINDER_DEBUG_USER_ERROR  = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION   = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE         = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER        = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION = 1U << 5,
	BINDER_DEBUG_READ_WRITE         = 1U << 6,
	BINDER_DEBUG_USER_REFS          = 1U << 7,
	BINDER_DEBUG_THREADS            = 1U << 8,
	BINDER_DEBUG_TRANSACTION        = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER        = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS      = 1U << 12,
	BINDER_DEBUG_PRIORITY_CAP       = 1U << 13,
	BINDER_DEBUG_SPINLOCKS          = 1U << 14,
};

static uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR |
		 BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION ;
module_param_named(debug_mask, binder_debug_mask, uint, S_IWUSR | S_IRUGO);

static char *binder_devices_param = CONFIG_ANDROID_BINDER_DEVICES;
module_param_named(devices, binder_devices_param, charp, 0444);

static DECLARE_WAIT_QUEUE_HEAD(binder_user_error_wait);
static int binder_stop_on_user_error;

static int binder_set_stop_on_user_error(const char *val,
				struct kernel_param *kp)
{
	int ret;
	
	ret = param_set_int(val, kp);
	if(binder_stop_on_user_error < 2)
		wake_up(&binder_user_error_wait);
	return ret;
}
module_param_call(stop_on_user_error, binder_set_stop_on_user_error,
						param_get_int, &binder_stop_on_user_error, S_IWUSR | S_IRUGO);
#define binder_debug(mask, x...)\
	do{\
		if(binder_debug_mask & mask) \
			pr_info(x);\
	}while(0)
		
#define binder_user_error(x...)\
do{\
	if(binder_debug_mask & BINDER_DEBUG_USER_ERROR)\
		pr_info(x);\
	if(binder_stop_on_user_error)\
		binder_stop_on_user_error = 2;\
}while(0)
	

#define to_flat_binder_object(hdr)\
	container_of(hdr, struct flat_binder_object, hdr);
	
#define to_binder_fd_object(hdr) container_of(hdr, struct binder_fd_object, hdr)

#define to_binder_buffer_object(hdr)\
	container_of(hdr, struct binder_buffer_object, hdr)
	
#define to_binder_fd_array_object(hdr)\
		container_of(hdr, struct binder_fd_array_object, hdr)
		
		
		
enum binder_stat_types {
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};

struct binder_stats {
	atomic_t br[_IOC_NR(BR_FAILED_REPLY) + 1];
	atomic_t bc[_ICO_NR(BC_REPLY_SG) + 1];
	atomic_t obj_created[BINDER_STAT_COUNT];
	atomic_t obj_deleted[BINDER_STAT_COUNT];
};

static struct binder_stats binder_stats;

static inline void binder_stats_deleted(enum binder_stat_types type)
{
	atomic_inc(&binder_stats.obj_deleted[type]);
}

static inline void binder_stats_created(enum binder_stat_types type)
{
	atomic_inc(&binder_stats.obj_created[type]);
}

struct binder_transaction_log_entry {
	int debug_id;
	int debug_id_done;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
	int return_error_line;
	uint32_t return_error;
	uint32_t return_error_param;
	const char *context_name;
};
struct binder_transaction_log {
	atomic_t cur;
	bool full;
	struct binder_transaction_log_entry entry[32];
};

static struct binder_transaction_log binder_transaction_log;
static struct binder_transaction_log binder_transaction_log_failed;

static struct binder_transaction_log_entry *binder_transaction_log_add(
	struct binder_transaction_log *log)
{
	struct binder_transaction_log_entry *e;
	unsigned int cur = atomic_inc_return(&log->cur);
	
	if(cur >= ARRAY_SIZE(log->entry))
		log->full = 1;
	e = &log->entry[cur % ARRAY_SIZE[log->entry];
	WRITE_ONCE(e->debug_id_done, 0);
	
	/** 
	** write-barrier to synchronize access to e->debug_id_done.
	** We make sure the initialized 0 value is seen before
	** memset() other fields are zeroed by memset.
	**/
	smp_wmb();
	memset(e, 0, sizeof(*e));
	return e;
}

struct binder_context {
	struct binder_node *binder_context_mgr_node;
	struct mutex context_mgr_node_lock;
	
	kuid_t binder_context_mgr_uid;
	const char *name;
};

struct binder_devices {
	struct hlist_node hlist;
	struct miscdevice miscdev;
	struct binder_context context;
};

/**
** struct binder_work - work enqueued on a worklist
** @entry :  node enqueued on list 
** @type  :  type of work to be performed
**
** There are separate work lists for proc, thread, and node(async).
**/

struct binder_work {
	struct list_head entry;
	
	enum {
		BINDER_WORK_TRANSACTION  = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_RETUR_ERROR,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	}type;
};


struct binder_error {
	struct binder_work work;
	uint32_t cmd;
};


/** 
** struct_binder_node  - binder node bookkeeping
** @debug_id : unique ID for debugging
**              (invariant after initialized)
** @lock :   lock for node fields
** @work:     worklist element for node work
**            (protected by @proc->inner_lock)
** @rb_node: element for proc->nodes_tree
**           (protected by @proc->inner_lock)
** @dead_node: element for binder_dead_nodes list
**           (protected by binder_dead_nodes_lock)
** @proc :  binder_proc that owns this node 
**           (invariant after initialized)
** @refs :  list for references on this node 
**           (protected by @lock)
** @internal_strong_refs: used to  take strong referencess when 
**                 initiating a transaction
**                 (protected by @proc->inner_lock if @proc and by @lock)
** @lock_strong_refs: strong user refs from local process
**                  (protected by @proc->inner_lock if @proc  and by @lock)
** @tmp_refs:  temporyary kernel refs
**             (protected by @proc->inner_lock while @proc
**              is valid, and by binder_dead_nodes_lock
**              if @proc is NULL.During inc/dec and node release
**              it is also protected by @lock to provide safety
**              as the node dies and @proc becomes NULL)
** @ptr:     userspace pointer for node
**           (invariant , no lock needed)
** @cookie:  userspace cookie for node 
**           (invariant, no lock  needed)
** @has_stong_ref: userspace notified of strong ref 
**           (protected by @proc->inner_lock if @proc
**            and by @lock
** @pending_strong_ref: userspace has acked notification of strong ref 
**           (protected by @proc->inner_lock if @proc 
**            and by @lock)
** @has_weak_ref: userspace notified of weak ref 
**                (protected by @proc->inner_lock if @proc and by @lock)
** @pending_weak_ref: userspace has acked notification of weak ref 
**                (protected by @proc->inner_lock if @proc and by @lock)
** @accept_fds:    file descriptor operations supported for node 
**                 (invariant after initialized)
** @mim_priority:   minimum scheduling priority
**                  (invariant after initialized)
** @async_todo:     list of async work items
**                  (protected by @proc->inner_lock)
**
** Bookkeeping structure for binner nodes.
**/
struct binder_node {
	int debug_id;
	spinlock_t lock;
	struct binder_work work;
	union {
		struct rb_node rb_node;
		struct hlist_node dead_node;
	};
	struct binder_proc *proc;
	struct hlist_head refs;
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	int tmp_refs;
	binder_uintptr_t ptr;
	binder_uintptr_t cookie;
	struct {
		/** 
		** bitfield elements protected by
		** proc inner_lock
		**/
		u8 has_strong_ref:1;
		u8 has_weak_ref:1;
		u8 pending_weak_ref:1;
	};
	
	struct {
		/**
		** invariant after initialization
		**/
		u8 accept_fds:1;
		u8 min_priority;
	};
	bool has_async_transaction;
	struct list_head async_todo;
};

struct binder_of_death {
	/**
	** @work worklist element for death notifications
	**    (protected by inner_lock of the proc that 
	**   this ref belongs to)
	**/
	struct binder_work work;
	binder_uintptr_t cookie;
};

/**
** struct_binder_ref_data  - binder_ref counts and id 
** @debug_id : unique ID for the ref
** @desc:      unique userspace handle for ref 
** @strong:     strong ref count(debugging only if not locked)
** @weak:  weak ref count(debugging only if not locked)
**
** Structure to hold ref count and ref id information. Since
** the actual ref can only be accessed with a lock, this structure
** is used to return information about the ref to callers of 
**ref inc/dec functions.
**/

struct binder_ref_data {
	int debug_id;
	uint32_t desc;
	int strong;
	int weak;
};

/**
** struct binder_ref - struct to track references on nodes
** @data : binder_ref_data containing id, handle,and current refcount
** @rb_node_desc: node for lookup by @data.desc in proc's rb_tree
** @rb_node_node: node for lookup by @node in proc's rb_tree
** node_entry: list entry for node->refs list in target node 
**             (protected by @node->lock)
** @proc :   binder_proc containing ref 
** @node:   binder_node of target node.When cleaning up a 
**          ref for deletion in binder_clearup_ref, a non-NULL 
**           @node indicates the node must be freed
** @death:   pointer to death notification (ref_death) if requested
**          (protected by @node->lock)
**
** Structure to track references from procA to target node(on procB).This
** struct is unsafe to access without holding @proc->outer_lock.
**/
struct binder_ref {
	/** Lookups needed **/
	/** node+ proc => ref(transaction) */
	/** desc + proc => ref(transaction, inc/dec ref) */
	/* node => refs + procs(proc exit) */
	struct binder_ref_data data;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct hlist_node node_entry;
	struct binder_proc *proc;
	struct binder_node *node;
	struct binder_ref_death *death;
};














































































































































































































































