/**
** init/noinitramfs.c
**
** Copyright(C) 2006, NXP Semiconductors, All 
**
** This program is free 
**
**/
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/kdev_t.h>
#include <linux/syscalls.h>

/**
** Create a simple rootfs that is similar to the default initramfs
**/
static int __init default_rootfs(void)
{
	int err;
	
	err = sys_mkdir((const char __user __force *)"/dev", 0755);
	if(err < 0)
		goto out;
	
	err = sys_mknod((const char __user __force *)"/dev/console",
			S_IFCHR | S_IR_USR | S_IWUSR,
			new_encode_dev(MKDEV(5,1)));
	if(err < 0)
		goto out;
	
	err = sys_mkdir((const char __user __force *)"/root", 0700);
	if(err < 0)
		goto out;
	
	return 0;
	
out:
	printk(KERN_WARNING"Failed to create a rootfs\n");
	return err;
}

rootfs_initcall(default_rootfs);

































