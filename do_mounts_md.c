/**
** Many of the syscalls used in this file expect some of the arguments
** to be __user pointers not __kernel pointers. To limit the sparse
** noise, turn off sparse checking for this file.
**/

#ifdef __CHECKER__
#undef __CHECKER__
#warning "Sparse checking disabled for this file"
#endif

#include <linux/delay.h>
#include <linux/raid/md_u.h>
#include <linux/raid/md_p.h>

#include "do_mounts.h"

/**
** When md(and any require personalities) are compiled into the kernel
** (not a module), arrays acan be assembles are boot time using with AUTODETECT
** where specially marked partitions are registed with md autodetect_dev(),
** and with MD_BOOT where devices to be collected are given on the boot line 
** with md=.....
** The code for that is here.
**/

#ifdef CONFIG_MD_AUTODETECT
static int __initdata raid_noautodetect;
#else
static int __initdata raid_noautodetect = 1;
#endif
static int __initdata raid_autopart;

static struct {
	int minor;
	int partitioned;
	int level;
	int chunk;
	char *device_names;
} md_setup_args[256] __initdata;

static int md_setup_ents __initdata;

/**
** Parse the command - line parameters given our kernel, but do not 
** actually try to invoke the MD device now; that is handled by 
** md_setup_drive after the low-level disk drivers have initialised.
**
**/
static int __initdata md_setup(char *str)
{
	int minor, level, factor, fault, partitioned = 0;
	char *pername = "";
	char *str1;
	int ent;
	
	if(*str == 'd') {
		partitioned = 1;
		str++;
	}
	
	if(get_option(&str, &minor) != 2) { /** MD Number **/
		printk(KERN_WARNING "md:Too few arguments supplied to md=.\n");
		return 0;
	}
	str1 = str;
	for(ent = 0; ent < md_setup_ents; ent++)
		if(md_setup_args[ent].minor == minor &&
		md_setup_args[ent].partitioned == partitioned) {
		printk(KERN_WARNING "md:md=%s%d, Specialed more than once."
			"Replacing previous defintion.\n", partitioned ? "d": "", minor);
		break;
	}
	
	if(ent >= ARRAY_SIZE(md_setup_args)) {
		printk(KERN_WARNING "md: md=%s%d - too many md initialisations\n", partitioned ? "d":"", minor);
		return 0;
	}
	if(ent >= md_setup_ents)
		md_setup_ents++;
	switch(get_option(&str, &level)) { /** RAID level **/
	case 2: /** could be 0 or -1 .. */
		if(level == 0 || level == LEVEL_LINEAR ) {
			if(get_option(&str, &factor) != 2 ||
				get_option(&str, &fault) != 2) {
				printk(KERN_WARNING "md: Too few arguments supplied to md=.\n");
				return 0;
			}
			md_setup_args[ent].level = level;
			md_setup_args[ent].chunk = 1 << (factor + 12);
			if(level == LEVEL_LINEAR)
				pername = "linear";
			else 
				pername = "raid0";
			break;
		}
		/** FALL THROUGH **/
	case 1: /** the first device is numberic **/
		str = str1;
		/** FALL THROUGH **/
	case 0:
		md_setup_args[ent].level = LEVEL_NONE;
		pername = "super-block";
	}
	
	printk(KERN_INFO "md: Will configure md%d (%s) from %s, below.\n",
		minor, pername, str);
	md_setup_args[ent].device_names = str;
	md_setup_args[ent].partitioned = partitioned;
	md_setup_args[ent].minor = minor;
	
	return 1;
}





















