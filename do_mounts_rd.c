/**
** Many of the syscalls used in this file expect some of the arguments
** to be __user pointers not __kernel pointers. To limit the sparse
** noise, turn off sparse checking for this file.
**/

#ifdef __CHECKER__
#undef __CHECKER__
#warning "Sparse checking disabled for this file "
#endif

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/minix_fs.h>
#include <linux/ext2_fs.h>
#include <linux/romfs_fs.h>
#include <uapi/linux/cramfs_fs.h>
#include <linux/initrd.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "do_mounts.h"
#include "../fs/squashfs/squashfs_fs.h"

#include <linux/decompress/generic.h>

int  __initdata rd_prompt = 1; /** 1 = prompt for RAM disk, 0 = don't prompt **/

static int __init prompt_ramdisk(char *str)
{
	rd_prompt = simple_strtol(str, NULL, 0) & 1;
	return 1;
}

__setup("prompt_ramdisk=", prompt_ramdisk);

int __initdata rd_image_start; /** starting block # of image **/
static int __init ramdisk_start_setup(char * str)
{
	rd_image_start = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("ramdisk_start=", ramdisk_start_setup);

static int __init crd_load(int in_fd, int out_fd, decompress_fn deco);

/**
** This routine tries to find a RAM disk image to load, and returns the 
** number of blocks to read for a non-compressed image, 0 if  the image 
** is a compressed image, and -1 if an image with the right magic
** numbers could not be found.
**
** We currently check for the following magic numbers:
**  minix
**  ext2
**  romfs
**  cramfs
**  squashfs
** gzip 
** bzip2
** lzma
** xz 
** lzo
** lz4
**/
static int __init
identify_ramdisk_image(int fd, int start_block, decompress_fn *decompressor)
{
	const int size = 512;
	struct minix_super_block *minixsb;
	struct romfs_super_block *romfssb;
	struct cramfs_super *cramfsb;
	struct squashfs_super_block *squashfsb;
	int nblocks = -1;
	unsigned char *buf;
	const char *compress_name;
	unsigned long n;
	
	buf = kmalloc(size, GFP_KERNEL);
	if(!buf)
		return -ENOMEM;
	
	minixsb = (struct minix_super_block *) buf;
	romfssb = (struct romfs_super_block *) buf;
	cramfsb = (struct cramfs_super *) buf;
	squashfsb = (struct squashfs_super_block *) buf;
	memset(buf, 0xe5, size);
	
	/** 
	** Read lock 0 to test for compressed kernel
	**/
	sys_lseek(fd, start_block * BLOCK_SIZE, 0);
	sys_read(fd, buf, size);
	
	*decompressor = decompress_method(buf, size, &compress_name);
	if(compress_name) {
		printk(KERN_NOTICE "RAMDISK:%s image found at block %d\n",
			compress_name, start_block);
		if(!*decompressor)
			printk(KERN_EMERG
				"RAMDISK:%s decompressor not configured!\n",
				compress_name);
		nblocks = 0;
		goto done;
	}
	
	/** romfs  is at block zero too **/
	if(romfsb->word0 == ROMSB_WORD0 &&
		romfsb->word1 == ROMSB_WORD1) {
		printk(KERN_NOTICE 
			"RAMDISK: romfs filesystem found at block %d\n",
			start_block);
		nblocks = (ntohl(romfsb->size) + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}
	
	if(cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE 
			"RAMDISK: cramfs filesystem found at block %d\n",
			start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
		
	}
	
	/** squashfs is at block zero too **/
	if(le32_to_cpu(squashfsb->s_magic) == SQUASHFS_MAGIC) {
		printk(KERN_NOTICE 
			"RAMDISK:squashfs filesystem found at block %d\n",
			start_block);
		nblocks = (le64_to_cpu(squashfsb->bytes_used) + BLOCK_SIZE - 1)
			>> BLOCK_SIZE;
		goto done;
	}
	
	/**
	** Read 512 bytes further to check if cramfs is padded **/
	
	sys_lseek(fd, start_block *BLOCK_SIZE + 0x200, 0);
	sys_read(fd, buf, size);
	
	if(cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE
			"RAMDISK: cramfs filesystem found at block %d\n",
			start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}
	
	/**
	** Read block 1 to test for minix and ext2 superblock
	**/
	sys_lseek(fd, (start_block + 1) *BLOCK_SIZE , 0);
	sys_read(fd, buf, size);
	
	/** Try minix **/
	if(minixsb->s_magic == MINIX_SUPER_MAGIC ||
		minixsb->s_magic == MINIX_SUPER_MAGIC2) {
		printk(KERN_NOTICE 
			"RAMDISK: Minix filesystem found at block %d\n",
			start_block);
		nblocks = minixsb->s_nzones << minixsb->s_log_zone_size;
		goto done;
	}
	
	/** Try ext2 **/
	n = ext2_image_size(buf)
	if(n) {
		printk(KERN_NOTICE
			"RAMDISK: ext2 filesystem found  at block %d\n",
			start_block);
		nblocks = n;
		goto done;
	}
	
	printk(KERN_NOTICE
		"RAMDISK:Couldn't find valid RAM disk image starting at %d.\n",
			start_block);

done:
	sys_lseek(fd, start_block *BLOCK_SIZE, 0);
	kfree(buf);
	return nblocks;

}






















































































































