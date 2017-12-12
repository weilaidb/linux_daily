/**
** linux/init/main.c
** 
** Copyright(C) 1991, 1992 
**
** Gk 2/5/95 - Changed to support mounting root fs via NFS
** Added initrd & change_root:
**/

#define DEBUG /** Enable initcall_debug **/

#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmode.h>
#include <linux/vmalloc.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcpudate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/kmemcheck.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/fs.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched_clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>


static int kernel_init(void *);

extern void init_IRQ(void);

extern void fork_init(void);

extern void radix_tree_init(void);

/**
** Debug helper: via this flag we know that we are in 'early bootup code'
** where only the boot processer is running with IRQ disabled. This means
** two things - IRQ must not be enabled before the flag is cleared and some 
** operations which are not allowed with IRQ disabled are allowed while the 
** flag is set .
**/
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/**
** Boot command - line arguments
**/
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/** Default late time init is NULL. archs can override this later. **/
void (*__initdata late_time_init)(void);

/** Untouched command line saved by arch-specific code **/
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/** Untouched saved command line(eg. for /proc)*/
char *saved_command_line;
/** Command line for parameter parsing **/
static char *static_command_line;
/** Command line for per-initcall parameter parsing **/
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/** 
** Used to generate warnings if static_key manipulation functions are used 
before jump_label_init is called.
**/

bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/**
** If set, this is an indication to the drivers that reset the underlying 
** device before going ahead with the initialization otherwise driver might 
** rely on the BIOS and skip the reset operation.

** This is useful if kernel is booting in an unreliable environment.
** For ex. kdump situation where previous kernel has crashed, BIOS has been 
** skipped and devices will be in unknown state.
**/
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS + 2] = {"init", NULL};
const char *envp_init[MAX_INIT_ENVS + 2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;
	
	p = __setup_start;
	do {
		int n = strlen(p->str);
		if(parameqn(line, p->str,n )) {
			if(p->early) {
				/** Already done in parse_early_param ?
				** (Needs exact match on param part).
				** Keep iterating, as we have early 
				** params and __setups of same names 8(*/
				if(line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	}while(p < __setup_end);
	
	return had_early_param;
}

/**
** This should be approx 2 Bo *oMips to start(note initial shift), and will 
** still work even if initially too large, it will just take slightly longer 
**/
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;
	
	/**
	** Only update loglevel value when a correct setting was passed,
	** to prevent blind crachsed(when loglevel being set to 0) that 
	** are quite hard to debug 
	**/
	if(get_option(&str,&newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}
	return -EINVAL;
}















































