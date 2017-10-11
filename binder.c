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













































































































































































































































