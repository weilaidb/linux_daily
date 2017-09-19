#define DEBUG /* Enable initcall_debug*/


static int kernel_init(void *);

extern void init_IRQ(void);
extern void fork_init(void);
extern void radix_tree_init(void);

/* Debug helper: via this flag we know that we are in 'early bootup code'  
*  Where only the boot processor is running with IRQ disabled. This means
*  two things - IRQ must not be enabled before the flag is cleared and some 
*  operations which are not allowed with IRQ disabled are allowed while the 
*  flag is set.
*/

bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;

EXPORT_SYMBOL(system_state);

/*
* Boot command-line arguments
*/

#define MAX_INIT_ARGS CONFIG_INIT_EVN_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later.
*/
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/*
Untoched saved command line (eg. for /proc) */
char *saved_command_line;

/*Command line for parameter parsing */
static char *static_command_line;
 
/*  Command line for per-initcall parameter parsing  */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
* Used to generagte warnings if static_key manipulation functions are used
* before jump_label_init is called.
*/
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
** If set, this is an indication to the drivers that reset the underlying 
** device before going ahead with the initialization otherwirse driver might
** rely on the BIOS and skp the reset operation.
**
** This is useful if kernel is booting in an unreliable environment.
** For ex, kdump situation whre previous kernel has crashed, BIOS has been
** skipped and devices will be in unknown state.
*/
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static init__init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

static const char *argv_init[MAX_INIT_ARGS + 2] =  {"init", NULL};
const char *envp_init[MAX_INIT_ENVS + 2] = {"HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{

	const struct obj_kernel_param *p;
	bool had_early_param = false;
	p = __setup_start;
	do {

		int n = strlen(p->str);
		if(parameqn(line, p->str, n)) {
			if(p->early) {
				/* A_lready done in parse_early_param ?
				** (Needs exact match on param para).
				** Keep interating, as we can have early
				** params and __setups of same names .
				*/
				if(line[n] == '\0' || line[n] == "=")
					had_early_param = true;
			} else if(!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n)) {
				return true;
			}
		}
		p++;

	}while (p < __setup_end);

	
	return had_early_param;

}

/* This should be approx 2 Bo*oMips to start(note initial shift), and will still work
** even if initially too large, it will just take slightly longer
**
*/
unsigned long loops_per_jiffy = (1 << 12);
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
	/*
	** Only update loglevel value when a correct setting was passed,
	** to prevent blind crashed( when loglevel being set to 0) that 
	** are quiet hard to debug
	*/
	if(get_option(&str, &newlevel))
	{
		console_loglevel = newlevel;
		return 0;
	}
	return -EINVAL;
}

early_param("loglevel", loglevel);

/* Change NUL term back to "=", to make "param" the whole string. */
static int __init repair_env_string(char *param, char *val,
						const char *unused, void *arg)
{
	if(val) {
		/* param =val or param="val"? */
		if(val == param + strlen(param) + 1)
			val[-1] = "=";
		else if(val == param + strlen(param) + 2) {
			val[-2]= "=";
			memmove(val-1, val, strlen(val) + 1);
			val--;
		}
		else
			BUG();
	}
	return 0;

}



/*  Anything after -- gets handed straight to innit. */
static int __init set_init_arg(char *param, char *val,
				const char *unused, void *arg)
{
	unsigned int i;
	if(panic_later)
		return 0;

	repair_env_string(param, val, unused, NULL);

	for(i = 0; argv_init[i]; i++) {
		if(i == MAX_INIT_ARGS)
		{
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}

	argv_init[i] = param;
	return 0;
	
	

}


/*
* Unknown boot options get handed to init, unless they look like
* unused parameters (modprobe will find them in /proc/cmdline).
*
*/
static int __init unknown_bootoption(char *param, char *val,
			const char *unused, void *arg)
{
	repaire_env_string(param,val, unused, NULL);
	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter */
	if(strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if(panic_later)
		return 0;

	if(val){
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++)
		{
			panic_later = "env";
			panic_param = param;
		}

		if(!strncmp(param, envp_init[i], val - param))
			break;
	}
	else
	{
		/*Command line option */
		unsigned int i;
		for(i =0; argv_init[i];i++)
		{
			if (i == MAX_INIT_ARGS)
			{	
				panic_later = "init";
				panic_param = param;
			}
		}
		envp_init[i] = param;
	}

	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/* 
	** In case LILO is going to boot us with default
	** it prepends "auto" before the whole cmdline which makes
	** the shell think it should execute a script with such name.
	** So we ignore all arguments entered _before_ init=...[MJ]
	*/
	for (i = 0; i < MAX_INIT_ARGS;i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;
	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for(i = 1;i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CUPS;
static inline void setup_nr_cpu_ids(void) {}
static inline void smp_prepare_cpus(unsigned int maxcpus){  }
#endif

/* We need to store the untoched command line for future reference.
** We also need to store the touched command line since the parameter 
** parsing is performed in place, and we should allow a component to 
** store reference of name/value for future reference.
*/
static void __init setup_command_line(char *command_line)
{
	saved_command_line = 
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	initcall_command_line = 
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	static_command_line = memblock_virt_alloc(strlen(command_line) + 1, 0);
	strcpy(saved_command_line, boot_command_line);
	strcpy(static_command_line, command_line);
}

/*
* We need to finalize in a non-__init function or else race conditions
* between the root thread and the init thread may cause start_kernel to 
* be reaped by free_initmem before the root thread has processed to 
* cpu_idle.
*
* gcc-3.4 accidentally inlines this function, so use noinline.
*/

static __initdata DECLARE_COMPLETION(kthreadd_done);

static noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;
	
	rcu_scheduler_starting();
	
	
}






















































































