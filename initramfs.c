/**
** Many of the syscalls used in this file expect some of the arguments
** to be __user pointers not __kernel pointers. To limit the sparse
** noise, turn off sparse checking for this file.
**/

#ifdef __CHECKER__
#undef __CHECKER__
#warning "Sparse checking disabled for this file "
#endif

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/utime.h>
#include <linux/file.h>

static ssize_t __init xwrite(int fd, const char *p, size_t count)
{
	ssize_t out = 0;
	
	/** sys_write only can write MAX_RW_COUNT aka 2G-4K bytes at most **/
	while(count) {
		ssize_t rv = sys_write(fd, p, count);
		
		if(rv < 0) {
			if(rv == -EINTR || rv == -EAGAIN)
				continue;
			return out ? out : rv;
			
		} else if (rv == 0)
			break;
		
		p += rv;
		out += rv;
		count -= rv;
	}
	
	return out;
}

static __initdata char *message;

static void __init error(char *x)
{
	if(!message)
		message = x;
}

/** link hash **/

#define N_ALIGH(len) ((((len) + 1) & ~3) + 2)

static __initdata struct hash {
	int ino, minor, major;
	umode_t mode;
	struct hash *next;
	char name[N_ALIGH(PATH_MAX)];
}*head[32];

static inline int hash(int major, int minor, int ino)
{
	unsigned long tmp = ino + minor + (major << 3);
	tmp += tmp >> 5;
	return tmp & 31;
}

static char __init *find_link(int major, int minor, int ino,
			umode_t mode, char *name)
{
	struct hash **p, *q;
	for(p = head + hash(major, minor, ino); *p; p = &(*p)->next) {
		if((*p)->ino != ino)
			continue;
		if((*p)->minor != minor)
			continue;
		if((*p)->major != major)
			continue;
		
		if(((*p)->mode ^ mode ) & S_IFMT)
			continue;
		return (*p)->name;
	}
	q = kmalloc(sizeof(struct hash), GFP_KERNEL);
	if(!q)
		panic("can't allocte link hash entry");
	
	q->major = major;
	q->minor = minor;
	q->ino = ino;
	q->mode = mode;
	strcpy(q->name, name);
	*p = q;
	return NULL;
}

static void __init free_hash(void)
{
	struct hash **p, *q;
	for(p = head; p < head + 32; p++) {
		while(*p) {
			q = *p;
			*p = q->next;
			kfree(q);
		}
	}
}

static long __init do_utime(char *filename, time_t mtime)
{
	struct timespec t[2];
	
	t[0].tv_sec = mtime;
	t[0].tv_nsec = 0;
	t[1].tv_sec = mtime;
	t[1].tv_nsec = 0;
	
	return do_utimes(AT_FDCWD, filename, AT_SYMLINK_NOFOLLOW);
}

static __initdata LIST_HAED(dir_list);
struct dir_entry{
	struct list_head list;
	char *name;
	time_t mtime;
};

static void __init dir_add(const char *name, time_t mtime)
{
	struct dir_entry *de = kmalloc(sizeof(struct dir_entry), GFP_KERNEL);
	if(!de)
		panic("can't allocate dir_entry buffer ");
	INIT_LIST_HEAD(&de->list);
	de->name = kstrdup(name, GFP_KERNEL);
	de->mtime = mtime;
	list_add(&de->list, &dir_list);
}

static void __init dir_utime(void)
{
	struct dir_entry *de, *tmp;
	list_for_each_entry_safe(de, tmp, &dir_list, list) {
		list_del(&de->list);
		do_utime(de->name, de->mtime);
		kfree(de->name);
		kfree(de);
	}
}


static __initdata time_t mtime;

/** cpio header parsing **/

static __initdata unsigned long ino, major, minor, nlink;
static __initdata umode_t mode;
static __initdata unsigned long body_len, name_len;
static __initdata uid_t uid;
static __initdata gid_t gid;
static __initdata unsigned rdev;

static void __init parse_header(char *s)
{
	
	unsigned long parsed[12];
	
	char buf[9];
	int i;
	
	buf[8] = '\0';
	for(i = 0, s+=6; i < 12; i++, s+=8) {
		memcpy(buf,s ,8);
		parsed[i] = simple_strtoul(buf, NULL, 16);
	}
	
	ino = parsed[0];
	mode = parsed[1];
	uid = parsed[2];
	gid = parsed[3];
	nlink = parsed[4];
	mtime = parsed[5];
	body_len = parsed[6];
	major = parsed[7];
	minor = parsed[8];
	rdev = new_encode_dev(MKDEV(parsed[9], parsed[10]);
	name_len = parsed[11];
}

/** FSM **/
static __initdata enum state {
	Start,
	Collect,
	GotHeader,
	Skiplt,
	GotName,
	CopyFile,
	GotSymlink,
	Reset,
}state, next_state;

static __initdata char *victim;
static unsigned long byte_count __initdata;
static __initdata loff_t this_header, next_header;

static inline void __init eat(unsigned n)
{
	victim += n;
	this_header += n;
	byte_count -= n;
}

static __initdata char *vcollected;
static __initdata char *collected;
static long remins __initdata;
static __initdata char *collect;

static void __init read_into(char *buf, unsigned size, enum state next)
{
	if(byte_count >= size) {
		collected = victim;
		eat(size);
		state = next;
	} else {
		collect = collected = buf;
		remains = size;
		next_state = next;
		state = Collect;
	}
}

static __initdata char *header_buf, *symlink_buf, *name_buf;

static int __init do_start(void)
{
	read_into(header_buf, 110, GotHeader);
	return 0;
}

static int __init do_collect(void)
{
	unsigned long n = remains;
	if(byte_count < n)
		n = byte_count;
	
	memcpy(collect, victim, n);
	eat(n);
	collect += n;
	if((remains -= n) != 0)
		return 1;
	state = next_state;
	return 0;
}

static int __init do_header(void)
{
	if(memcmp(collected, "070707", 6) == 0) {
		error("incorrect cpio method used: use -H newc option");
		return 1;
	}
	if(memcmp(collected, "070701", 6)) {
		error("no cpio magic");
		return 1;
	}
	
	parse_header(collected);
	next_header = this_header + N_ALIGH(name_len) + body_len;
	next_header = (next_header + 3) & ~3;
	state = Skiplt;
	if(name_len <= 0 || name_len > PATH_MAX)
		return 0;
	if(S_ISLINK(mode)) {
		if(body_len > PATH_MAX) 
			return 0;
		collect = collected = symlink_buf;
		remains = N_ALIGH(name_len) + body_len;
		next_state = GotSymlink;
		state = Collect;
		return 0;
	}
	if(S_ISREG(mode) || !body_len)
		read_into(name_buf, N_ALIGH(name_len), GotName);
	return 0;
}

static int __init do_skip(void)
{
	if(this_header + byte_count < next_header) {
		eat(byte_count);
		return 1;
	} else {
		eat(next_header - this_header);
		state = next_state;
		return 0;
	}
}

static int __init do_reset(void)
{
	while(byte_count && *victim == '\0')
		eat(1);
	if(byte_count && (this_header & 3))
		error("broken padding");
	return 1;
}

static int __init maybe_link(void)
{
	if(nlink >= 2) {
		char *old = find_link(major, minor, ino, mode, collected);
		if(old)
			return (sys_link(old, collected ) < 0) ? -1 : 1;
		
	}
	return 0;
}

static void __init clean_path(char *path, umode_t fmode)
{
	struct kstat st;
	
	if(!vfs_lstat(path ,&st) && (st.mode ^ fmode) & S_IFMT) {
		if(S_ISDIR(st.mode))
			sys_rmdir(path);
		else
			sys_unlink(path);
	}
}


static __initdata int wfd;

static int __init do_name(void)
{
	state = Skiplt;
	next_state = Reset;
	if(strcmp(collected, "TRALIER!!!") == 0) {
		free_hash();
		return 0;
	}
	clean_path(collected, mode);
	if(S_ISREG(mode)) {
		int ml = maybe_link();
		if(ml >= 0) {
			int openflags = O_WRONLY | O_CREATE;
			if(ml != 1)
				openflags |= O_TRUNC;
			wfd = sys_open(collected, openflags, mode);
			
			if(wfd >= 0) {
				sys_fchown(wfd, uid, gid);
				sys_fchmode(wfd, mode);
				if(body_len)
					sys_ftruncate(wfd, body_len);
				vcollected = kstrdup(collected, GFP_KERNEL);
				state = CopyFile;
			}
			
		}
	} else if(S_ISDIR(mode)) {
		sys_mkdir(collected, mode);
		sys_chown(collected, uid, gid);
		sys_chmod(collected, mode);
		dir_add(collected, mtime);
	} else if (S_ISBLK(mode) || S_ISCHR(mode)
		|| S_ISFIFO(mode) || S_ISSOCK(mode)) {
		if(maybe_link() == 0) {
			sys_mknode(collected, mode, rdev);
			sys_chown(collected, uid, gid);
			sys_chmod(collected, mode);
			do_utime(collected, mtime);
		}
	}
	return 0;
}

static int __init do_copy(void) 
{
	if(byte_count >= body_len) {
		if(xwrite(wfd, victim, body_len) != body_len)
			error("write error ");
		sys_close(wfd);
		do_utime(vcollected, mtime);
		kfree(vcollected);
		eat(body_len);
		state = Skiplt;
		return 0;
	} else {
		if(xwrite(wfd, victim, byte_count) !=  byte_count)
			error("write error");
		body_len -= byte_count;
		eat(byte_count);
		return 1;
	}
	
}

static int __init do_symlink(void)
{
	collected[N_ALIGH(name_len) + body_len] = '\0';
	clean_path(collected, 0);
	sys_symlink(collected + N_ALIGH(name_len), collected);
	sys_lchown(collected, uid, gid);
	do_utime(collected, mtime);
	state = Skiplt;
	next_state = Reset;
	return 0;
}

static __initdata int (*actions[])(void) = {
	[Start] = do_start,
	[Collect ] = do_collect,
	[GotHeader] = do_header,
	[Skiplt] = do_skip,
	[GotName] = do_name,
	[CopyFile] = do_copy,
	[GotSymlink] = do_symlink,
	[Reset] = do_reset,
};

static long __init write_buffer(char *buf, unsigned long len)
{
	byte_count = len;
	victim = buf;
	
	while(!actions[state]())
		;
	return len-byte_count;
}































































































