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

enum binder_deferred_state {
	BINDER_DEFERRED_PUT_FILES = 0x1,
	BINDER_DEFERRED_FLUSH     = 0x2,
	BINDER_DEFERRED_RELEASE   = 0x3,
};

/** 
** struct binder_proc - binder process bookkepping
** @proc_node:  element for binder_procs list
** @threads:   rbtree of binder_threads in this pro
**             (protected by @inner_lock )
** @nodes:   rbtree of binder nodes associated with
**           this proc ordered by node->ptr
**           (protected by @inner_lock)
** @refs_by_desc :  rbtree of refs ordered by ref->desc
**            (protected by @outer_lock)
** @waiting_threads: threads currently waiting for proc work
**             (protected by @inner_lock)
** @pid:  PID of group_leader of process
**          (invariant after initialized)
** @tsk:      task_struct for group_leader of process
**          (invariant after initialized)
** @deferred_work_node: element for binder_deferred_list
**           (protected by binder_deferred_lock)
** @deferred_work:  bitmap of deferred work to performed
**           (protected by binder_deferred_lock)
** @is_dead: process is dead and awaiting free
**           when outstanding transactions are cleanup up
**           (protected by @inner_lock)
** @todo:     list of work for this process
**            (protected by @inner_lock)
** @wait:    wait queue head to wait for proc work
**            (invariant after initialized)
** @stats:   per-process binder statistics
**            (atomics, no lock needed)
** @delivered_death:  list of delivered death notification
**            (protected by @inner_lock)
** @max_threads: cap on number of binder threads
**            (protected by @inner_lock)
** @requested_threads: number of binder threads requested but not
**            yet started. In current implementation, can 
** 			   only be 0 or 1.
** @requested_threads_started: number binder threads started
**            (protected by @inner_lock)
** @tmp_ref:   temporary references to indicate proc is in use 
**             (protected by @inner_lock)
** @default_priority: default scheduler priority
**             (invariant after initialized)
** @debugfs_entry:  debugfs node 
** @alloc:   binder allocator bookkeeping
** @context:  binder_context for this proc
**            
** @inner_lock:  can nest under outer_lock and/or node lock
** @outer_lock: no nesting under innor or node lock
**
**
** Bookkeeping structure for binder processes
**/
struct binder_proc {
	struct hlist_node proc_node;
	struct rb_node threads;
	struct rb_node nodes;
	struct rb_node refs_by_desc;
	struct rb_node refs_by_node;
	struct list_head waiting_threads;
	int pid;
	struct task_struct *tsk;
	struct files_struct *files;
	struct hlist_node deferred_work_node;
	int deferred_work;
	bool is_dead;
	
	struct list_head todo;
	wait_queue_head_t wait;
	struct binder_stats stats;
	struct list_head delivered_death;
	int max_threads;
	int requested_threads;
	int requested_threads_started;
	int tmp_ref;
	long default_priority;
	struct dentry *debugfs_entry;
	struct binder_alloc alloc;
	struct binder_context *context;
	spinlock_t inner_lock;
	spinlock_t outer_lock;
};

enum {
	BINDER_LOOPER_STATE_REGISTERED = 0x01,
	BINDER_LOOPER_STATE_ENTERED    = 0x02,
	BINDER_LOOPER_STATE_EXITED     = 0x04,
	BINDER_LOOPER_STATE_INVALID    = 0x08,
	BINDER_LOOPER_STATE_WAITING    = 0x10,
	BINDER_LOOPER_STATE_POLL       = 0x20，
};
/**
** struct binder_thread - binder thread bookkeeping
** @proc:   binder process for this thread
**          (invariant after initialization)
** @rb_node:    element for proc->threads rbtree
**          (protected by @proc->inner_lock)
** @waiting_thread_node: element for @proc->waiting_threads list
**           (protected by @proc->inner_lock)
** @pid:    PID for this thread
**          (invariant after initialized)
** @looper:    bitmap of looping state 
**             (only accessed by this thread)
** @looper_needs_return: looping thread needs to exit driver
**             (no lock needed)
** @transaction_stack: stack of in-process transaction for this thread
**             (protected by @proc->inner_lock)
** @todo:   list of work to do for this thread 
**              (protected by @proc->inner_lock)
** @return_error :  transaction errors reported by this thread
**                (only accessed by this thread)
** @reply_error:   transaction errors reported by target thread
**                (protected by @proc->inner_lock)
** @wait: wait queue for thread work
** @stats:  per-thread statistics
**           (atomics,no lock thread)
** @tmp_ref:   temporary reference to indicate thread is in use 
**           (atomic since @proc->inner_lock cannot always be acquired)
** @is_dead: thread is dead and awaiting free
**           when outstanding transactions are cleaned up
**           (protected by @proc->inner_lock)
**
**
**
**
** Bookkeeping structure for binder threads.
**/
struct binder_thread {
	struct binder_proc *proc;
	struct rb_node rb_node;
	struct list_head waiting_thread_node;
	int pid;
	int looper; /** only modified by this thread **/
	bool looper_need_return; /** can be written by other thread **/
	struct binder_transaction *transaction_stack;
	struct list_head todo;
	struct binder_error return_error;
	struct binder_error reply_error;
	wait_queue_head_t wait;
	struct binner_stats stats;
	atomic_t tmp_ref;
	bool is_dead;
};

struct binder_transaction {
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	unsigned need_reply:1;
	/** unsigned is_dead:1 **/ /**not used at the moment */
	struct binder_buffer *buffer;
	unsigned int code;
	unsigned int flags;
	long priority;
	long saved_priority;
	kuid_t sender_euid;
	/**
	** @lock: protects @from, @to_proc, and @to_thread 
	**
	** @from,@to_proc, and @to_thread can be set to NULL
	** during thread teardown
	**/
	spinlock_t lock;
};

/** 
** binder_proc_lock() - Acquire outer lock for given binder_proc
**@proc:  struct binder_proc to accquire
**
** Acquires proc->outer_lock.Used to protect binder_ref
** structures associated with the given proc.
**/
#define binder_proc_lock(proc) _binder_proc_lock(proc, __LINE__)
static void 
_binder_proc_lock(struct binder_proc *proc, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
		"%s:line=%d\n", __func__, line);
	spin_lock(&proc->outer_lock);
}

/**
** binder_proc_unlock() - Release spinlock for given binder_proc
** @proc:  struct binder_proc to acquire
**
** Release lock acquired via binder_proc_lock()
**/
#define binder_proc_unlock(_proc) _binder_proc_unlock(_proc, __LINE__)
static void 
_binder_proc_unlock(struct binder_proc *proc, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
		"%s:line=%d\n", __func__, line);
	spin_unlock(&proc->outer_lock);
}

/**
** binder_inner_proc_lock() - Acquire inner lock for given binder_proc
** @proc: struct binder_proc to acquire
** 
** Acquires proc->inner_lock. Used to protect todo lists
**/
#define binder_inner_proc_lock(proc) _binder_inner_proc_lock(proc, __LINE__)
static void 
_binder_inner_proc_lock(struct binder_proc *proc, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
			"%s:line=%d\n", __func__, line);
	spin_lock(&proc->inner_lock);
}

/**
** binder_inner_proc_unlock() - Release inner lock for given binder_proc
** @proc:  struct binder_proc to acquire
** 
** Release lock acquired via binder_inner_proc_lock()
**/
#define binder_inner_proc_unlock(proc) _binder_inner_proc_unlock(proc, __LINE__)
static void 
_binder_inner_proc_unlock(struct binder_proc *proc, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
		"%s:line=%d\n",__func__, line);
	spin_unlock(&proc->inner_lock);
}

/**
** binder_node_lock - Acquire spinlock for given binder_node
** @node:   struct binder_node to acquire
**  
** Acquires node->lock. Used to protect binder_node fields.
**/
#define binder_node_lock(node) _binder_node_lock(node, __LINE__)
static void 
_binder_node_lock(struct binder_node *node, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
			"%s:line=%d\n", __func__,line);
	spin_lock(&node->lock);
}

/**
** binder_node_unlock() - Release spinlock for given binder_proc
** @node:  struct binder_node to acquire
**
** Release lock acquired via binder_node_lock()
**/
#define binder_node_unlock(node) _binder_node_unlock(node, __LINE__)
static void 
_binder_node_unlock(struct binder_node *node, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
			"%s:line=%d\n", __func__, line);
	spin_unlock(&node->lock);
}
/**
** binder_node_inner_lock() - Acquire node and inner locks
** @node:  struct binder_node to acquire
**
** Acquires node->lock. If node->proc also acquires
** proc->inner_lock.Used to protect binder_node fields.
**/
#define binder_node_inner_lock(node) _binder_node_inner_lock(node, __LINE__)
static void 
_binder_node_inner_lock(struct binder_node *node, int line)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
		"%s:line=%d\n", __func__, line);
	spin_lock(&node->lock);
	if(node->proc)
		binder_inner_proc_lock(node->proc);
}

/**
** binder_node_inner_unlock() - Release node and inner locks
** @node: struct binder_node to acquire
**  
** Release lock acquired via binder_node_inner_lock()
**/
#define binder_node_inner_unlock(node) _binder_node_inner_unlock(node, __LINE__)
static void 
_binder_node_inner_unlock(struct binder_node *node, int line)
{
	struct binder_proc *proc = node->proc;
	
	binder_debug(BINDER_DEBUG_SPINLOCKS,
			"%s:line=%d\n", __func__, line);
	spin_lock(&node->lock);
}

static bool binder_worklist_empty_ilocked(struct list_head *list)
{
	return list_empty(list);
}

/**
** binder_worklist_empty() - Check if no items on the work list 
** @proc: binder_proc associated with list 
** @list: list to check 
**
** Return: true i there are no items on list, else false
**/
static bool binder_worklist_empty(struct binder_proc *proc,
					struct list_head *list)
{
	bool ret;
	
	binder_inner_proc_lock(proc);
	ret = binder_worklist_empty_ilocked(list);
	binder_inner_proc_unlock(proc);
	return ret;
}
static void 
binder_enqueue_work_ilocked(struct binder_work *work,
				struct list_head *target_list)
{
	BUG_ON(target_list == NULL);
	BUG_ON(work->entry.next && !list_empty(&work->entry));
	list_add_tail(&work->entry, target_list);
}

/**
** binder_enqueue_work() - Add an item to the work list 
** @proc:  binder_proc associated with list
** @work:  struct binder_work to add to list 
** @target_list: list to add work to 
**
** Adds the work to the specified list. Asserts that work 
** is not already on a list.
**/
static void 
binder_enqueue_work(struct binder_proc *proc,
			struct binder_work *work,
			struct list_head *target_list)
{
	binder_inner_proc_lock(proc);
	binder_enqueue_work_ilocked(work, target_list);
	binder_inner_proc_unlock(proc);
}

static void 
binder_dequeue_work_ilocked(struct binder_work *work)
{
	list_del_init(&work->entry);
}

/**
** binder_dequeue_work() - Removes an item from the work list 
** @proc:  binder_proc associated with list 
** @work: struct binder_work to remove from list 
**
** Removes the specified work item from whatever list it is on .
** Can safely be called if work is not on any list.
**/
static void 
binder_dequeue_work(struct binder_proc *proc, struct binder_work *work)
{
	binder_inner_proc_lock(proc);
	binder_dequeue_work_ilocked(work);
	binder_inner_proc_unlock(proc);
}

static struct binder_work *binder_dequeue_work_head_ilocked(
				struct list_head *list)
{
	struct binder_work *w;
	
	w = list_first_entry_or_null(list, struct binder_work, entry);
	if(w)
		list_del_init(&w->entry);
	return w;
}

/**
** binder_dequeue_work_head() - Dequeues the item at head of list
** @proc: binder_proc associated with list 
** @list: list to dequeue head 
**
** Removes the head of the list if there are items on the list 
** 
** Return: pointer  dequeued binder_work, NULL if list was empty.
**/
static struct binder_work *binder_dequeue_work_head(
				struct binder_proc *proc,
				struct list_head *list)
{
	struct binder_work *w;
	binder_inner_proc_lock(proc);
	w = binner_dequeue_work_head_ilocked(list);
	binder_inner_proc_unlock(proc);
	return w;
}

static void 
binder_defer_work(struct binder_proc *proc, enum binder_deferred_state defer);
static void binder_free_thread(struct binder_thread *thread);
static void binder_free_proc(struct binder_proc *proc);
static void binder_inc_node_tmpref_ilocked(struct binder_node *node);

static int task_get_unused_fd_flags(struct binder_proc *proc,int flags)
{
	struct files_struct *files = proc->files;
	unsigned long rlim_cur;
	unsigned long irqs;
	
	if(files == NULL)
		return -ESRCH;
	
	if(!lock_task_sighand(proc->tsk, &irqs))
		return -EMFILE;
	
	rlim_cur = task_rlimit(proc->tsk, RLIMIT_NOFILE);
	unlock_task_sighand(proc->tsk, &irqs);
	
	return __alloc_fd(files,0, rlim_cur, flags);
}

/**
** copied from fd_install
**/
static void task_fd_install(
	struct binder_proc *proc, unsigned int fd, struct file *file)
{
	if(proc->file)
		__fd_install(proc->files, fd, line);
}

/**
** copied from sys_close
**/
static long task_close_fd(struct binder_proc *proc,unsigned int fd)
{
	int retval;
	
	if(proc->files == NULL)
		return -ESRCH;
	
	retval = __close_fd(proc->files, fd);
	/** can't restart close syscall because file table entry was cleared **/
	if(unlikely(retval == -ERESTARTSYS ||
			retval == -ERESTARTNOINTR ||
			retval == -ERESTARTNOHAND ||
			retval == -EReSTART_RESTARTBLOCK))
		retval = -EINTR;
	return retval;
}

static bool binder_has_work_ilocked(struct binder_thread *thread, bool do_proc_work)
{
	return !binder_worklist_empty_ilocked(&thread->todo) ||
			thread->looper_need_return ||
			(do_proc_work &&
			 !binder_worklist_empty_ilocked(&thread->proc->todo));
}

static bool binder_has_work(struct binder_thread *thread, bool do_proc_work)
{
	bool has_work;
	
	binder_inner_proc_lock(thread->proc);
	has_work = binder_has_work_ilocked(thread, do_proc_work);
	binder_inner_proc_unlock(thread->proc);
	
	return has_work;
}

static bool binder_available_for_proc_work_ilocked(struct binder_thread *thread)
{
	return !thread->transaction_stack &&
		binder_worklist_empty_ilocked(&threa->todo) &&
		(thread->looper & (BINDER_LOOPER_STATE_ENTERED |
			BINDER_LOOPER_STATE_REGISTERED));
}

static void binder_wakeup_poll_threads_ilocked(struct binder_proc *proc, bool sync)
{
	struct rb_node *n;
	struct binder_thread *thread;
	
	for(n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) {
		thread = rb_entry(n, struct binder_thread, rb_node);
		if(thread->looper & BINDER_LOOPER_STATE_POLL && 
			binder_available_for_proc_work_ilocked(thread)) {
			if(sync)
				wake_up_interruptile_sync(&threa->wait);
			else 
				wake_up_interruptile(&thread->wait);
		}
	}
}



/**
** binder_select_thread_ilock() - selects a thread for doing proc work.
** @proc: process to select a thread form 
** 
** Note that calling this function moves the thread off the waiting_threads
** list, so it can only be woken up by the caller of this function, or a 
** signal. Therefore, callers *should* always wake up the thread this function
** returns.
**
** Return: If there's a thread currently waiting for process work,
**         returns that thread. Otherwise returns NULL.
**/

static struct binder_thread *
binder_select_thread_ilocked(struct binder_proc *proc)
{
	struct binder_thread *thread;
	
	assert_spin_locked(&proc->inner_lock);
	thread = list_first_entry_or_null(&proc->waiting_threads,
			struct binder_thread,
			waiting_thread_node);
	
	if(thread)
		list_del_init(&thread->waiting_thread_node);
	
	return thread;
}

/**
** binder_wakeup_thread_ilocked() - wakes up a thread for doing proc work.
** @proc: process to wake up a thread in 
** @thread: specific thread to wake-up (may be NULL)
** @sync: whether to do a synchronous wake-up 
**
** This function wakes up a thread in the @proc process.
** The caller may provide a specific thread to wak-up in 
** the @thread parameter. If @thread is NULL, this function
** will wake up threads that have called poll().
**
** Note that for this function to work as expected, callers
** should first call binder_select_thread() to find a thread 
** to handle the work(if they don't have a thread already),
** and pass the result into the @thread parameter.
**/
static void binder_wakeup_thread_ilocked(struct binder_proc *proc,
			struct binder_thread *thread, bool sync)
{
		assert_spin_locked(&proc->inner_lock);
		
		if(thread) {
			if(sync)
				wake_up_interruptible_sync(&thread->wait);
			else
				wake_up_interruptible(&thread->wait);
			return;
		}
		
		/** 
		** Didn't find a thread waiting for proc work; this can happen
		** in two scenarios:
		** 1. All threads are busy handling transactions
		**    In that case,one of those threads should call back into 
		**    the kernel driver soon and pick up this work.
		** 2.Threads are using the (e)poll interface,in which case 
		**   they may be blocked on the waitqueue without having been
		**   over all threads not handling transaction work, and 
		**   wake them all up. We wake all because we don't know whether 
		**   a thread that called into (e)poll is handling non-binder 
		**  work currently.
		**/
		binder_wakeup_poll_threads_ilocked(proc, sync);
}


static void binder_wakeup_proc_ilocked(struct binder_proc *proc)
{
	struct binder_thread *thread = binder_select_thread_ilocked(proc);
	
	binder_wakeup_thread_ilocked(proc, thread /* sync = */ false);
}

static void binder_set_nice(long nice)
{
	long min_nice;
	
	if(can_nice(current, nice)) {
		set_user_nice(current, nice);
		return;
	}
	min_nice = rlimit_to_nice(rlimit(RLIMIT_NICE));
	binder_debug(BINDER_DEBUG_PRIORITY_CAP,
		"%d: nice value %ld not allowed use %ld instead\n",
		current->pid, nice, min_nice);
	set_user_nice(current, min_nice);
	if(min_nice <= MAX_NICE)
		return;
	binder_user_error("%d RLIMIT_NICE not set\n", current->pid);
}
static struct binder_node *binder_get_node_ilocked(struct binder_proc *proc,
					binder_uintptr_t ptr)
{
	struct rb_node *n = proc->nodes.rb_node;
	struct binder_node *node;
	
	assert_spin_locked(&proc->inner_lock);
	
	while(n) {
		node = rb_entry(n, struct binder_node, rb_node);
		
		if(ptr < node->ptr)
			n = n->rb_left;
		else if (ptr > node->ptr)
			n = n->rb_right;
		else {
			/**
			** take  an implicit weak reference
			** to ensure node stays alive until
			** call to binder_put_node()
			**/
			binder_inc_node_tmpref_ilocked(node);
			return node;
		}
	}
	return NULL;
}

static struct binder_node *binder_get_node(struct binder_proc *proc,
					binder_uintptr_t ptr)
{
	struct binder_node *node;
	
	binder_inner_proc_lock(proc);
	node = binder_get_node_ilocked(proc, ptr);
	binder_inner_proc_unlock(proc);
	return node;
}







































































































































































































































