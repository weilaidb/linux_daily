 /**
 ** Posix message queues filesystem for Linux.
 **/
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sysctl.h>
#include <linux/poll.h>
#include <linux/msg.h>
#include <linux/mqueue.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/netlink.h>
#include <linux/syscalls.h>
#include <linux/audit.h>
#include <linux/signal.h>
#include <linux/mutext.h>
#include <linux/nsproxy.h>
#include <linux/pid.h>
#include <linux/ipc_namespace.h>
#include <linux/user_namespace.h>
#include <linux/slab.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
#include <linux/sched/user.h>

#include <net/sock.h>
#include "util.h"


#define MQUEUE_MAGIC 0x19800202
#define DIRENT_SIZE 20
#define FILENT_SIZE 80

#define SEND 0 
#define RECV 1

#define STATE_NONE 0
#define STATE_READY 1

struct posix_msg_tree_node {
	struct rb_node rb_node;
	struct list_head msg_list;
	int priority;
};

struct ext_wait_queue { /** queue of sleeping tasks **/
	struct task_struct *task;
	struct list_head list;
	struct msg_msg *msg; /** ptr of loaded message **/
	int state; /** one of STATE_* values **/
};

struct mqueue_inode_info {
	spinlock_t lock;
	struct inode vfs_inode;
	wait_queue_head_t wait_q;
	
	struct rb_root msg_tree;
	struct posix_msg_tree_node *node_cache;
	struct mq_attr attr;
	
	struct sigevent notify;
	struct pid *notify_owner;
	struct user_namespace *notify_user_ns;
	struct user_struct *user; /** user who created, for accounting **/
	struct sock *notify_sock;
	struct sk_buff *notify_cookie;
	
	/** for tasks waiting for free space and messages, respectively **/
	struct ext_wait_queue e_wait_q[2];
	
	unsigned long size; /** size of queue in memory (sum of all msgs) **/
};

static const struct inode_operations mqueue_dir_inode_operations;
static const struct file_operations mqueue_file_operations;
static const struct super_operations mqueue_super_ops;
static void remove_notification(struct mqueue_inode_info *info);

static struct kmem_cache *mqueue_inode_cachep;
static struct ctl_table_header * mq_sysctl_table;

static inline struct mqueue_inode_info *MQUEUE_I(struct inode *inode)
{
	return container_of(inode, struct mqueue_inode_info, vfs_inode);
}

/** 
** This routine should be called with the mq_lock held.
**/
static inline struct ipc_namespace *__get_ns_from_inode(struct inode *inode)
{
	return get_ipc_ns(inode->i_sb->s_fs_info);
}

static struct ipc_namespacee *get_ns_from_inode(struct inode *inode)
{
	struct ipc_namespace *ns;
	
	spin_lock(&mq_lock);
	ns = __get_ns_from_inode(inode);
	spin_unlock(&ms_lock);
	
	return ns;
}

/** Auxiliary functions to manipulate message's list **/
static int msg_insert(struct msg_msg *msg, struct mqueue_inode_info *info)
{
	struct rb_node **p, *parent = NULL;
	struct posix_msg_tree_node *leaf;
	
	p = &info->msg_tree.rb_node;
	while(*p) {
		parent = *p;
		leaf = rb_entry(parent, struct posix_msg_tree_node, rb_node);
		
		if(likely(leaf->priority == msg->m_type))
			goto insert_msg;
		else if(msg->m_type < leaf->priority)
			p = &(*p)->rb_left;
		else 
			p = &(*p)->rb_right;
		
	}
	if(info->node_cache) {
		leaf = info->node_cache;
		info->node_cache = NULL;
	} else {
		leaf = kmalloc(sizeof(*leaf), GFP_ATOMIC);
		if(!leaf)
			return -ENOMEM;
		INIT_LIST_HEAD(&leaf->msg_list);
	}
	leaf->priority = msg->m_type;
	rb_link_node(&leaf->rb_node, parent, p);
	rb_insert_color(&leaf->rb_node, &info->msg_tree);
	
insert_msg:
	info->attr.mq_curmsgs++;
	info->qsize += msg->m_ts;
	list_add_tail(&msg->m_list, &leaf->msg_list);
	
	return 0;
}

static inline struct msg_msg *msg_get(struct mqueue_inode_info *info)
{
	struct rb_node **p, *parent = NULL;
	struct posix_msg_tree_node *leaf;
	struct msg_msg *msg;
	
try_again:
	p  =&info->msg_tree.rb_node;
	while(*p) {
		parent = p;
		/**
		** During insert, low priorities go to the left and high to the 
		** right. On receive, we want the highest priorities first, so 
		** walk all the way to the left 
		**/
		p = &(*p)->rb_right;
	}
	if(!parent) {
		if(info->attr.mq_curmsgs) {
			pr_warn_once("Inconsitency in POSIX message queue, "
			"no tree element, but supposedly messages"
			"should exist!\n");
			info->attr.mq_curmsgs = 0;
		}
		return NULL;
	}
	leaf = rb_entry(parent, struct posix_msg_tree_node, rb_node);
	if(unlikely(list_empyt(&leaf->msg_list))) {
		pr_warn_once("Inconsitency in POSIX message queue,"
			"empty leaf node but we haven't implemented "
			"lazy leaf delete!\n");
		rb_erase(&leaf->rb_node, &info->msg_tree);
		if(info->node_cache) {
			kfree(leaf);
		} else {
			info->node_cache = leaf;
		}
		goto try_again;
	} else {
		msg = list_first_entry(&leaf->msg_list,
				struct msg_msg, m_list);
		list_del(&msg->m_list);
		if(list_empyt(&leaf->msg_list)) {
			rb_erase(&leaf->rb_node, &info->msg_tree);
			if(info->node_cache) {
				kfree(leaf);
			} else {
				info->node_cache = leaf;
			}
		}
	}
	info->attr.mq_curmsgs--;
	info->qsize -= msg->m_ts;
	return msg;
}

static struct inode *mqueue_get_inode(struct super_block *sb,
					struct ipc_namespace *ipc_ns, umode_t mode,
					struct mq_attr *attr)
{
	struct user_struct *u  = current_user();
	struct inode *inode;
	int ret = -ENOMEM;
	
	inode = new_inode(sb);
	if(!inode)
		goto err;
	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_mtime = inode->i_ctime = inode->i_atime = current_time(inode);
	
	if(S_ISREG(mode)) {
		struct mqueue_inode_info *info;
		unsigned long mq_bytes, mq_treesize;
		
		inode->i_fop = &mqueue_file_operations;
		inode->i_size = FILENT_SIZE;
		/** mqueue specific info **/
		info = MQUEUE_I(inode);
		spin_lock_init(&info->lock);
		init_waitqueue_head(&info->wait_q);
		INIT_LIST_HEAD(&info->e_wait_q[0].list);
		INIT_LIST_HEAD(&info->e_wait_q[1].list);
		info->notify_owner = NULL;
		info->notify_user_ns = NULL;
		info->qsize = 0;
		info->user = NULL; /** set when all is ok **/
		info->msg_tree = RB_BOOT;
		info->node_cache = NULL;
		memset(&info->attr, 0, sizeof(info->attr));
		info->attr.mq_maxmsg = min(ipc_ns->mq_msg_max,
					ipc_ns->mq_msg_default);
		info->attr.mq_msgsize = min(ipc_ns->mq_msgsize_max,
					ipc_ns->mq_msgsize_default);
		if(attr) {
			info->attr.mq_maxmsg = attr->mq_maxmsg;
			info->attr.mq_msgsize = attr->mq_msgsize;
		}
		/**
		** We used to allocate a static array of pointers and account 
		** the size of that array as well as one msg_msg struct per 
		** possible message into the queue size. That's no longer 
		** accurate as the queue is now an rbtree and will grow and 
		** shrink depending on usage patterns. We can, however, still 
		** accout one msg_msg struct per message, but the nodes are 
		** allocated depending on priority usage, and most programs 
		** only use one ,or a handful, of priorities. However , since 
		** this is pinned memory, we need to assume worst case, so that means the
		** min(mq_maxmsg, max_priorities) * struct posix_msg_tree_node.
		**/
		mq_treesize = info->attr.mq_maxmsg *sizeof(struct msg_msg) + 
				min_t(unsigned int, info->attr.mq_maxmsg, MQ_PRIO_MAX) *
				sizeof(struct posix_msg_tree_node);
		mq_bytes = mq_treesize + (info->attr.mq_maxmsg *
					info->attr.mq_msgsize);
					
		spin_lock(&mq_lock);
		if(u->mq_bytes + mq_bytes < u->mq_bytes ||
			u->mq_bytes + mq_bytes > rlimit(RLIMIT_MSGQUEUE)) {
			spin_unlock(&mq_lock);
			/** mqueue_evict_inode() release info->messages **/
			ret = -EMFILE;
			goto out_inode;
		}
		u->mq_bytes += mq_bytes;
		spin_unlock(&mq_lock);
		
		/** all is ok **/
		info->user = get_uid(u);
	} else if (S_iSDIR(mode)) {
		inc_nlink(inode);
		/** Some things misbehave if size == 0 on a directory **/
		inode->i_size = 2 * DIRENT_SIZE;
		inode->i_op = &mqueue_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
	}
	return inode;
	
out_inode:
	iput(inode);
	
err:
	return ERR_PTR(ret);
}

static int mqueue_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct ipc_namespace *ns = sb->s_fs_info;
	
	sb->s_iflags |= SB_I_NOEXEC | SB_I_NODEV;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = MQUEUE_MAGIC;
	sb->s_op = &mqueue_super_ops;
	
	inode = mqueue_get_inode(sb, ns , S_IFDIR | S_ISVTX | S_IRWXUGO, NULL);
	if(IS_ERR(inode))
		return PTR_ERR(inode);
	
	sb->s_root = d_make_root(inode);
	if(!sb->s_root)
		return -ENOMEM;
	
	return 0;
}

 static struct dentry *mqueue_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name,
				void *data)
{
	struct ipc_namespace *ns;
	if(flags & MS_KERNMOUNT) {
		ns = data;
		data = NULL;
	} else {
		ns = current->nsproxy->ipc_ns;
	}
	
	return mount_ns(fs_type, flags, data, ns, ns->user_ns, mqueue_fill_super);
}

static void init_once(void *foo)
{
	struct  mqueue_inode_info *p = (struct mqueue_inode_info *)foo;
	
	inode_init_once(&p->vfs_inode);
}

static struct inode *mqueue_alloc_inode(struct super_block *sb)
{
	struct mqueue_inode_info *ei;
	
	e = kmem_cache_alloc(mqueue_inode_cachep, GFP_KERNEL);
	if(!ei)
		return NULL;
	
	return &ei->vfs_inode;
}

static void mqueue_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(mqueue_inode_cachep, MQUEUE_I(inode));
}

static void mqueue_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, mqueue_i_callback);
}

static void mqueue_evict_inode(struct inode *inode)
{
	struct mqueue_inode_info *info;
	struct user_struct *user;
	unsigned long mq_bytes, mq_treesize;
	struct ipc_namespace *ipc_ns;
	struct msg_msg *msg;
	
	clear_inode(inode);
	
	if(S_ISDIR(inode->i_mode))
		return;
	
	ipc_ns = get_ns_from_inode(inode);
	info = MQUEUE_I(inode);
	spin_lock(&info->lock);
	while((msg = msg_get(info)) != NULL)
		free_msg(msg);
	kfree(info->node_cache);
	spin_unlock(&info->lock);
	
	/** Total amount of bytes accounted for the mqueue **/
	mq_treesize = info->attr.mq_maxmsg * sizeof(struct msg_msg) + 
		min_t(unsigned int, info->attr.mq_maxmsg, MQ_PRIO_MAX) *
		sizeof(struct posix_msg_tree_node);
		
	mq_bytes = mq_treesize + (info->attr.mq_maxmsg *
					info->attr.mq_msgsize);
	user = info->user;
	
	if(user) {
		spin_lock(&mq_lock);
		user->mq_bytes -= mq_bytes;
		/** 
		** get_ns_from_inode() ensures that the 
		** (ipc_ns == sb->s_fs_info) is either a valid ipc_ns
		** to which we now hold a reference, or it is NULL.
		** We can't put it here under mq_lock, though.
		**/
		if(ipc_ns)
			ipc_ns->mq_queues_count--;
		spin_unlock(&mq_lock);
		free_uid(user);
		
	}
	
	if(ipc_ns)
		put_ipc_ns(ipc_ns);
}

static int mqueue_create(struct inode *dir, struct dentry *dentry,
					umode_t mode, bool excl)
{
	struct inode *inode;
	struct mq_attr *attr = dentry->d_fsdata;
	int error;
	struct ipc_namespace *ipc_ns;
	
	spin_lock(&mq_lock);
	ipc_ns = __get_ns_from_inode(dir);
	if(!ipc_ns) {
		error = -EACCESS;
		goto out_unlock;
	}
	
	if(ipc_ns->mq_queues_cout >= ipc_ns->mq_queues_max &&
		!capable(CAP_SYS_RESOURCE)) {
		error = -ENOSPC;
		goto out_unlock;
	}
	
	ipc_ns->mq_queues_count++;
	spin_unlock(&mq_lock);
	
	inode = mqueue_get_inode(dir->i_sb, ipc_ns, mode, attr);
	if(IS_ERR(inode)) {
		
		error = PTR_ERR(inode);
		spin_lock(&mq_lock);
		ipc_ns->mq_queues_count--;
		goto out_unlock;
	}
	
	put_ipc_ns(ipc_ns);
	dir->i_size += DIRENT_SIZE;
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	
	d_instantiate(dentry, inode);
	dget(dentry);
	
out_unlock:
	spin_unlock(&mq_lock);
	if(ipc_ns)
		put_ipc_ns(ipc_ns);
	
	return error;
}

static int mqueue_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	dir->i_size -= DIRENT_SIZE;
	drop_nlink(inode);
	dput(dentry);
	return 0;
}

/**
** This is routine for system read from queue file.
** To avoid mess with doing here some sort of mq_receive we allow 
** to read only queue size & notification (the only values 
** that are interesting from user point of view and aren't accessible 
** through std routines )
**/
static ssize_t mqueue_read_file(struct file *filp, char __user *u_data,
				size_t count, loff_t *off)
{
	struct mqueue_inode_info *info = MQUEUE_I(file_inode(filp));
	char buffer[FILENT_SIZE];
	ssize_t ret;
	
	spin_lock(&info->lock);
	snprintf(buffer, sizeof(buffer),
		"QSIZE:%-10u NOTIFY:%-5d SIGNO:%-5d NOTIFY_PID:%-6d\n",
		info->qsize,
		info->notify_owner ? info->notify.sigev_notify: 0,
		(info->notify.sigev_notify == SIGEV_SIGNAL) ?
			info->notify.sigev_signo : 0,
			pid_vnr(info->notify_owner));
	spin_unlock(&info->lock);
	buffer[sizeof(buffer) - 1] = '\0';
	
	ret = simple_read_from_buffer(u_data, count, off, buffer,
				strlen(buffer));
	if(ret <= 0)
		return ret;
	
	file_inode(filp)->i_atime = file_inode(filp)->i_ctime = current_time(file_inode(filp));
	
	return ret;
}

struct mqueue_flush_file(struct file *filp, fl_owner_t id)
{
	struct mqueue_inode_info *info = MQUEUE_I(file_inode(filp));
	
	spin_lock(&info->lock);
	if(task_tgid(current) == info->notify_owner)
		remove_notification(info);
	
	spin_unlock(&info->lock);
	
	return 0;
}

static unsigned int mqueue_poll_file(struct file *filp, struct poll_table_struct *poll_tab)
{
	struct mqueue_inode_info *info = MQUEUE_I(file_inode(filp));
	int retval = 0;
	
	poll_wait(filp, &info->wait_q, poll_tab);
	
	spin_lock(&info->lock);
	if(info->attr.mq_curmsg)
		retval |= POLLIN | POLLRDNORM;
	if(info->attr.mq_curmsgs < info->attr.mq_maxmsg)
		retval |= POLLOUT | POLLWRNORM;
	
	spin_unlock(&info->lock);
	
	return retval;
}


 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 