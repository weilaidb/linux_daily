/**
** many of the syscalls used in this file expect some of the arguments
** to be __user pointers not __kernel pointers. To limit the sparse
** noise, turn of sparse checking for this file.
**/
#ifdef __CHECKER__
#undef __CHECKER__
#warning "Sparse checking disabled for this file"
#endif

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fd.h>
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/ramfs.h>
#include <linux/shmem_fs.h>

#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/nfs_mount.h>

#include "do_mount.h"

int __initdata rd_doload; /** 1= load RAM disk, 0 = don't load */

int root_mountflags = MS_RDONLY | MS_SILENT;
static char * __initdata root_device_name;
static char __initdata saved_root_name[64];
static int root_wait;

dev_t ROOT_DEV;

static int __init load_ramdisk(char *str)
{
	rd_doload = simple_strtol(str, NULL, 0) & 3;
	return 1;
}

__setup("load_ramdisk=", load_ramdisk);

static int __init readonly(char *str)
{
	if(*str)
		return 0;
	root_mountflags |= MS_RDONLY;
	return 1;
}

static int __init readwrite(char *str)
{
	if(*str)
		return 0;
	root_mountflags &= ~MS_RDONLY;
	return 1;
}

__setup("ro", readonly);
__setup("rw", readwrite);

#ifdef CONFIG_BLOCK
struct uuidcmp{
	const char *uuid;
	int len;
};

/**
** match_dev_by_uud - callback for finding a partition using its uuid
** @dev: device passed in by the caller
** @data: opaque pointer to the desired struct uuidcmp to match
**
** Return 1 if the device matches, and 0 otherwise.
**/
static int match_dev_by_uuid(struct device *dev, const void *data)
{
	const struct uuidcmp *cmp = data;
	struct hd_struct *part = dev_to_part(dev);
	
	if(!part->info)
		goto no_match;
	
	if(strncasecmp(cmp->uuid, part->info->uuid, cmp->len))
		goto no_match;
	
	return 1;
no_match:
	return 0;
}

/**
** devt_from_partuuid - looks up the dev_t of a partition by its UUID
** @uuid_str:  char array containing ascii UUID
**
** The function will return the first partition which contains a matching
** UUID value in its partion_meta_info struct. This does not search 
** by filesystem UUIDs.
**
** If @uuid_str is followed by a "/ PARTNROFF=%d", then the number will be 
** extracted and used as an offset from the partion identified by the UUID.
**
** Returns the matching dev_t on success or 0 on failure.
**/
static dev_t devt_from_partuuid(const char *uuid_str)
{
	dev_t res = 0;
	struct uuidcmp cmp;
	struct device *dev = NULL;
	struct gendisk *disk ;
	struct hd_struct *part;
	int offset = 0;
	bool clear_root_wait = false;
	char *slash;
	
	cmp.uuid = uuid_str;
	slash = strchr(uuid_str, '/');
	/** Check for optical partition number offset attributes. **/
	if(slash) {
		char c = 0;
		/** Explicitly fail on poor PARTUUID syntax. **/
		if(sscanf(slash + 1,
			"PARTNROFF=%d%c", &offset, &c)!= 1){
			clear_root_wait = true;
			goto done;
		}
		cmp.len = slash - uuid_str;
	} else {
		cmp.len = strlen(uuid_str);
	}
	
	if(!cmp.len) {
		clear_root_wait = true;
		goto done;
	}
	
	dev = class_find_device(&block_class, NULL, &cmp,
				&match_dev_by_uuid);
	if(!dev)
		goto done;
	
	res = dev->devt;
	
	/** Attempt to find the partition by offset **/
	if(!offset)
		goto no_offset;
	
	res = 0;
	disk = part_to_disk(dev_to_part(dev));
	part = disk_get_part(disk, dev_to_part(dev)->partno + offset);
	if(part) {
		res = part_dev(part);
		put_device(part_to_dev(part));
	}
	
no_offset:
	put_device(dev);
done:
	if(clear_root_wait){
		pr_err("VFS:PARTUUID= is invalid.\n"
			"Expected PARTUUID=<valid-uuid-id>[/PARTNROFF=%%d]\n");
		if(root_wait)
			pr_err("Disabling rootwait; root=is invalid.\n");
		root_wait = 0;
	}
	return res;
}

#endif


/**
** Convert a name into device number. We accept the following variants:
** 
** 1) <hex_major><hex_minor> device number in hexadecimal represents itself
**      no leading 0x, for eaxmaple b302.
** 2)/dev/nfs represents Root_NFS(0xff)
** 3)/dev/ <disk_name> represents the device number of disk
** 4)/dev/ <disk_name> <decimal> represents the device number
**      of partion - device number of disk plus the partion number
** 5)/dev/<disk_name>p<decimal> - same as the above, that form is 
**     used when disk name of partitioned desk ends on a digit.
** 6)PARTUUID=00112233-4455-6677-8899-AABBCCDDEEFF representing the 
**    unique id of a partion if the partion table provides it.
**    The UUID may be either an EFI/GPT UUID, or refer to an MSDOS
**    partition using the format SSSSSSSS-PP, where SSSSSSSS is a zero-
**    filled hex representation of the 32-bit "NT disk signature", and PP
**    is a zero-filled hex representation of the 1-based partition number.
**  7)PARTUUID=<UUID>/PARTNROFF=<int> to select a partition in relation to 
**     a partition with a known unique id.
**  8) <major>:<minor> major and minor number of the device separated by 
**      a colon.
**
**  If name doesn't have fall into the categories above, we return(0,0).
**  block_class is used to check if something is a disk name. If the disk
**  name contains slashes, the device name has them replaced with 
** bangs.
**/
dev_t name_to_dev_t(const char *name)
{
	char s[32];
	char *p;
	dev_t res = 0;
	int part;
	
#ifdef CONFIG_BLOCK
	if(strncmp(name, "PARTUUID=", 9) == 0) {
		name += 9;
		res = devt_from_partuuid(name);
		if(!res)
			goto fail;
		goto done;
		
	}
#endif
	if(strncmp(name, "/dev/", 5) != 0){
		unsigned maj, min, offset;
		char dummy;
		
		if(sscanf(name, "%u:%u%c", &maj, &min, &dummy) == 2) ||
			(sscanf(name, "%u:%u:%u:%c", &maj, &min, &offset, &dummy) == 3)){
			res = MKDEV(maj, min);
			if(maj != MAJOR(res) || min != MINOR(res))
				goto fail;
		} else {
			res = new_decode_dev(simple_strtoul(name, &p, 16));
			if(*p)
				goto fail;
		}
		goto done;
	}
	name += 5;
	res = Root_NFS;
	if(strcmp(name, "nfs") == 0)
		goto done;
	res = Root_RAM0;
	if(strcmp(name, "ram") == 0)
		goto done;
	
	if(strlen(name) > 31)
		goto fail;
	strcpy(s, name);
	
	for(p = s; *p; p++)
		if(*p == '/')
			*p = '!';
		
	res = blk_lookup_devt(s, 0);
	if(res)
		goto done;
	
	/** 
	** try non-existent, but valid partition, which may only exist
	** after revalidating the disk, like partitioned md devices
	**/
	while(p > s && isdigit(p[-1]))
		p--;
	if(p == s || !*p || *p == '0')
		goto fail;
	
	/** try disk name without <part number> **/
	part = simple_strtoul(p, NULL, 0);
	*p = '\0';
	res = blk_lookup_devt(s, part);
	if(res)
		goto done;
	
	/** try disk name without p<part number> */
	if(p < s + 2|| !isdigit(p[-2]) || p[-1] != 'p')
		goto fail;
	p[-1] = '\0';
	res = blk_lookup_devt(s, part);
	if(res)
		goto done;
	
fail:
	return 0;
done:
	return res;
}
EXPORT_SYMBOL_GPL(name_to_dev_t);

static int __init root_dev_setup(char *line)
{
	strlcpy(saved_root_name, line, sizeof(saved_root_name));
	return 1;
	
}
__setup("root=", root_dev_setup);

































































