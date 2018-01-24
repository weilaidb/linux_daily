/**
** Removed all the remaining kerneld mess 
** Catch the -EFAULT stuff properly 
** Use GFP_KERNEL for messages as in 1.2
** Fixed up the unchecked user space derefs 
** 
** /proc/sysvipc/msg support(c) 1999 Dragos A
**
** mostly rewritten, threadted and wake-one semanitics added
** MSGMAX limit removed, sysctl's added 
**
** support for audit of ipc object properites and permission changes
**
** namespaces support
**/
#include <linux/capability.h>
#include <linux/msg.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/security.h>
#include <linux/sched/wake_q.h>
#include <linux/syscalls.h>
#include <linux/audit.h>
#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>

#include <asm/current.h>
#include <linux/uaccess.h>
#include "util.h"

/** one msg_receiver structure for each sleeping receiver **/

struct msg_receiver {
	struct list_head r_list;
	struct task_struct *r_tsk;
	
	int r_mode;
	long r_msgtype;
	long r_maxsize;
	
	struct msg_msg *r_msg;
};

/** one msg_sender for each sleeping sender **/
struct msg_sender {
	struct list_head list;
	struct task_struct *tsk;
	size_t  msgsz;
};

#define SEARCH_ANY 1
#define SEARCH_EQUAL 2
#define SEARCH_NOTEQUAL 3
#define SEARCH_LESSEQUAL  4
#define SEARCH_NUMBER 5

#define msg_ids(ns) ((ns)->ids[IPC_MSG_IDS])

static inline struct msg_queue *msg_obtain_object(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = ipc_obtain_object_idr(&msg_ids(ns), id);
	
	if(IS_ERR(ipcp))
		return ERR_CAST(ipcp);
	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline struct msg_queue *msg_obtain_object_check(struct ipc_namespace *ns,
	int id)
{
	struct kern_ipc_perm *ipcp = ipc_obtain_object_check(&msg_ids(ns), id);
	
	if(IS_ERR(ipcp))
		return ERR_CAST(ipcp);
	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline void msg_rmid(struct ipc_namespace *ns, struct msg_queue *s)
{
	ipc_rmid(&msg_ids(ns), &s->q_perm);
}

static void msg_rcu_free(struct rcu_head *head)
{
	struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
	struct msg_queue *msq = container_of(p, struct msg_queue, q_perm);
	
	security_msg_queue_free(msq);
	kvfree(msq);
}

/**
** newque - Create a new msg queue 
** @ns: namespace
** @params: ptr to the structure that contains the key and msgflg
** 
** Called with msg_ids.rwsem held(writer)
**/
static int newque(struct ipc_namespace *ns, struct ipc_params *params)
{
	struct msg_queue *msq;
	int retval;
	key_t key = params->key;
	int msgflg = params->flg;
	
	msq = kvmalloc(sizeof(*msq), GFP_KERNEL);
	if(unlikely(!msq))
		return -ENOMEM;
	
	msq->q_perm.mode = msgflg & S_IRWXUGO;
	msq->q_perm.key = key;
	msq->q_perm.security = NULL;
	retval = security_msg_queue_alloc(msq);
	if(retval) {
		kvfree(msq);
		return retval;
	}
	msq->q_stime = msq->q_rtime = 0;
	msq->q_ctime = get_seconds();
	msq->q_cbytes = msq->q_qnum = 0;
	msq->q_qbytes = ns->msg_ctlmnb;
	msq->q_lspid = msq->q_lrpid = 0;
	INIT_LIST_HEAD(&msq->q_messages);
	INIT_LIST_HEAD(&msq->q_receivers);
	INIT_LIST_HEAD(&msq->q_senders);
	/** ipc_addid() locks msq upon success. **/
	retval = ipc_addid(&msg_ids(ns), &msq->q_perm, ns->msg_ctlmni);
	if(retval < 0) {
		call_rcu(&msq->q_perm.rcu, msg_rcu_free);
		return retval;
	}
	ipc_unlock_object(&msq->q_perm);
	rcu_read_unlock();
	
	return msq->q_perm.id;
}

static inline bool msg_fits_inqueue(struct msg_queue *msq, size_t  msgsz)
{
	return msgsz + msq->q_cbytes <= msq->q_qbytes &&
		1 + msq->q_qnum < = msq->q_qbytes;
}

static inline void ss_add(struct msg_queue *msq,
				struct msg_sender *mss, size_t msgsz)
{
	mss->tsk = current;
	mss->msgsz = msgsz;
	__set_current_state(TASK_INTERRUPTIBLE);
	list_add_tail(&mss->list, &msq->q_senders);
}

static inline void ss_del(struct msg_sender *mss)
{
	if(mss->list.next)
		list_del(&mss->list);
}

static void ss_wakeup(struct msg_queue *msq,
				struct wake_q_head *wake_q, bool kill)
{
	struct msg_sender *mss, *t;
	struct task_struct *stop_tsk = NULL;
	struct list_head *h = &msq->q_senders;
	
	list_for_each_entry_safe(mss, t, h, list) {
		if(kill)
			mss->list.next = NULL;
		
		/** 
		** Stop at the first task we don't wakeup,
		** we've already iterated the original
		** sender queue.
		**/
		else if (stop_tsk == mss->tsk)
			break;
		/**
		** We are not in an EIDRM scenario here, therefore
		** verify that we really need to wakeup the task,
		** To maintain current semanics and wakeup order,
		** move the sender to the tail on behalf of the 
		** blocked task.
		**/
		else if (!msg_fits_inqueue(msq, mss->msgsz)) {
			if(!stop_tsk)
				stop_tsk = mss->tsk;
			list_move_tail(&mss->list, &msq->q_senders);
			continue;
		}
		wake_q_add(wake_q, mss->tsk);
	}
}

static void expunge_all(struct msg_queue *msq, int res,
				struct wake_q_head *wake_q)
{
	struct msg_receiver *msr, *t;
	
	list_for_each_entry_safe(msr, t, &msq->q_receivers, r_list) {
		wake_q_add(wake_q, msr->r_tsk);
		WRITE_ONCE(msr->r_msg, ERR_PTR(res));
	}
}
/**
** freeque() wakes up waiter on the sender and receiver waiting queue,
** removes the message queue from message ID IDR, and cleans up all the 
** message associtaed with this queue.
**
** msg_ids.rwsem(writer) and the spinlock for this message queue are held 
** before freeque() is called. msg_ids.rwsem remains locked on exit.
**/
static void freeque(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
{
	struct msg_msg *msg, *t;
	struct msg_queue *msq = container_of(ipcp, struct msg_queue, q_perm);
	DEFINE_WAKE_Q(wake_q);
	
	expunge_all(msq, -EIDRM, &wake_q);
	ss_wakeup(msq, &wake_q, true);
	msg_rmid(ns, msq);
	ipc_unlock_object(&msq->q_perm);
	wake_up_q(&wake_q);
	rcu_read_unlock();
	
	list_for_each_entry_safe(msg, t, &msq->q_messages, m_list) {
		atomic_dec(&ns->msg_hdrs);
		free_msg(msg);
	}
	atomic_sub(msq->q_cbytes, &ns->msg_bytes);
	ipc_rcu_putref(&msq->q_perm, msg_rcu_free);
	
}


/**
** Called with msg_ids.rwsem and ipcp locked.
**/
static inline int msg_security(struct kern_ipc_perm *ipcp, int msgflg)
{
	struct msg_queue *msq = container_of(ipcp, struct msg_queue, q_perm);
	
	return security_msg_queue_associate(msq, msgflg);
}

SYSCALL_DEFINE2(msgge, key_t, key, int, msgflg)
{
	struct ipc_namespace *ns;
	static const struct ipc_ops msg_ops = {
		.getnew = newque,
		.associate = msg_security,
	};
	struct ipc_params = msg_params;
	ns = current->nsproxy->ipc_ns;
	
	msg_params.key = key;
	msg_params.flg = msgflg;
	
	
	return ipcget(ns, &msg_ids(ns), &msg_ops, &msg_params);
}

static inline unsigned long 
copy_msqid_to_user(void __user *buf, struct msqid64_ds *in, int version)
{
	switch(version) {
	case IPC_64:
		return copy_to_user(buf, in , sizeof(*in));
	case IPC_OLD:
	{
		struct msqid_ds out;
		
		memset(&out, 0, sizeof(out));
		
		ipc64_perm_to_ipc_perm(&in->msg_perm, &out.msg_perm);
		
		out.msg_stime = in->msg_stime;
		out.msg_rtime = in->msg_rtime;
		out.msg_ctime = in->msg_ctime;
		
		if(in->msg_cbytes > USHORT_MAX)
			out.msg_cbytes = USHORT_MAX;
		else 
			out.msg_cbytes = in->msg_cbytes;
		out.msg_lcbytes = in->msg_cbytes;
		
		if(in->msg_qnum > USHORT_MAX)
			out.msg_qnum = USHORT_MAX;
		else 
			out.msg_qnum = in->msg_qnum;
		
		if(in->msg_qbytes > USHORT_MAX)
			out.msg_qbytes = USHORT_MAX;
		else 
			out.msg_qbytes = in->msg_qbytes;
		out.msg_lqbytes = in->msg_qbytes;
		
		out.msg_lspid = in->msg_lspid;
		out.msg_lrpid = in->msg_lrpid;
		
		return copy_to_user(buf, &out, sizeof(out));
	}
	default:
		return -EINVAL;
	}
}

static inline unsigned long 
copy_msqid_from_user(struct msqid64_ds *out, void __user *buf, int version)
{
	switch(version) {
	case IPC_64:
		if(copy_from_user(out, buf, sizeof(*out)))
			return -EFAULT;
		return 0;
	case IPC_OLD:
	{
		struct msqid_ds tbuf_old;
		
		if(copy_from_user(&tbuf_old, buf, sizeof(tbuf_old)))
			return -EFAULT;
		
		out->msg_perm.uid = tbuf_old.msg_perm.uid;
		out->msg_perm.gid = tbuf_old.msg_perm.gid;
		out->msg_perm.mode = tbuf_old.msg_perm.mode;
		
		if(tbuf_old.msg_qbytes == 0) 
			out->msg_qbytes = tbuf_old.msg_lqbytes;
		else
			out->msg_qbytes = tbuf_old.msg_qbytes;
		
		return 0;
	}
	default:
		return -EINVAL;
	}
}

/**
** This function handles some msgctl commands which require the rwsem 
** to be held in write mode.
** NOTE: no locks must be held, the rwsem is taken inside this function.
**/
static int msgctl_down(struct ipc_namespace *ns, int msqid, int cmd,
				struct msqid_ds __user *buf, int version)
{
	struct kern_ipc_perm *ipcp;
	struct msgid64_ds uninitialized_var(msgid64);
	struct msg_queue *msq;
	int err;
	
	if(cmd == IPC_SET) {
		if(copy_msqid_from_user(&msqid64, buf, version))
			return -EFAULT;
	}
	down_write(&msg_ids(ns).rwsem);
	rcu_read_lock();
	
	ipcp = ipcctl_pre_down_nolock(ns, &msg_ids(ns), msqid, cmd, 
			&msqid64.msg_perm, msqid64.msg_qbytes);
	if(IS_ERR(ipcp)) {
		err = PTR_ERR(ipcp);
		goto out_unlock1;
	}
	
	msq = container_of(ipcp, struct msg_queue, q_perm);
	
	err = security_msg_queue_msgctl(msq, cmd);
	if(err)
		goto out_unlock1;
	switch(cmd) {
	case IPC_RMID:
		ipc_lock_object(&msq->q_perm);
		/** freeque unlocks the ipc object and rcu **/
		freeque(ns, ipcp);
		goto out_up;
	case IPC_SET:
	{
		DEFINE_WAKE_Q(wake_q);
		
		if(msqid64.msg_qbytes > ns->msg_ctlmnb &&
			!capable(CAP_SYS_RESOURCE)) {
			err = -EPERM;
			goto out_unlock1;
		}
		ipc_lock_object(&msq->q_perm);
		err = ipc_update_perm(&msqid64.msg_perm, ipcp);
		if(err)
			goto out_unlock1;
		msq->q_qbytes = msqid64.msg_qbytes;
		msq->q_ctime = get_seconds();
		/**
		** Sleeping receivers might be excluded by 
		** strickter permissions.
		**/
		expunge_all(msq, -EAGAI, &wake_q);
		/** Sleeping senders might be able to send 
		** due to a larger queue size..
		**/
		ss_wakeup(msq, &wake_q, false);
		ipc_unlock_object(&msq->q_perm);
		wake_up_q(&wake_q);
		
		goto out_unlock1;
	}
	default:
		err = -EINVAL;
		goto out_unlock1;
	}
	
out_unlock0:
	ipc_unlock_object(&msq->q_perm);
out_unlock1:
	rcu_read_unlock();
out_up:
	up_write(&msg_ids(ns).rwsem);
	return err;
}
















































































































