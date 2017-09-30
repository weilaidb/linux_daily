#define DEBUG

#include <linux/types.h> /** FIXME: kvm_para.h needs this */
#include <linux/stop_machine.h>
#include <linux/kvm_para.h>
#include <linux/uaccess.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/sport.h>
#include <linux/cpu.h>
#include <linux/pci.h>
#include <linux/smp.h>
#include <linux/syscore_ops.h>

#include <asm/cpufeature.h>
#include <asm/e820/api.h>
#include <asm/mtrr.h>
#include <asm/msr.h>
#include <asm/pat.h>

#include "mtrr.h"

/** arch_phys_wc_add returns an MTRR register index plus this offset. */
#define MTRR_TO_PHYS_WC_OFFSET 1000

u32 num_var_ranges;
static bool __mtrr_enabled;

static bool mtrr_enabled(void)
{
	return __mtrr_enabled;
}

unsigned int mtrr_usage_table[MTRR_MAX_VAR_RANGES];
static DEFINE_MUTEX(mtrr_mutex);

u64 size_or_mask, size_and_mask;
static bool mtrr_aps_delayed_init;

static const struct mtrr_ops *mtrr_ops[X86_VENDOR_NUM] __ro_after_init;
const struct mtr_ops *mtrr_if;

static void set_mtrr(unsigned int reg, unsigned long base,
				unsigned long size, mtrr_type type);

void __init set_mtrr_ops(const struct mtrr_ops *ops)
{
	if(ops->vendor && ops->vendor < X86_VENDOR_NUM)
		mtrr_ops[ops->vendor] = ops;
}

/** Return non-zero if we have the write-combing memory type */
static int have_wrcomb(void)
{
	struct pci_dev *dev;
	
	dev = pci_get_class(PCI_CLASS_BRIDGE_HOST << 8, NULL);
	if(dev != NULL) {
		/**
		** ServerWorks LE chipsets < rev 6 have problems with 
		** write-combing. Don't allow it and leave room for other
		** chipsets to be tagged.
		*/
		if(dev->vendor == PCI_VENDOR_ID_SERVERWORKS &&
			dev->device == PCI_DEVICE_ID_SERVERWORKS_LE &&
			dev->revision <= 5){
			pr_info("mtrr:ServerWorks LE rev < 6 detected. Write-combing disabled.\n");
			pci_dev_put(dev);
			return 0;
		}
		/** 
		** Intel 450NX errata # 23. Non ascending cacheline evictions to 
		** write combing memory may resulting in data corruption
		*/
		if(dev->vendor == PCI_VENDOR_ID_INTEL && 
			dev->device == PCI_DEVICE_ID_INTERL_82451NX) {
				pr_info("mtrr: Intel 450NX MMC detected. Write-combing disabled.\n");
				pci_dev_put(dev);
				return 0;
				
			}
			pci_dev_put(dev);
	}
	return mtrr_if->have_wrcomb ? mtrr_if->have_wrcomb() : 0;
	
}


/** This function returns the number of variable MTRRs */
static void __int set_num_var_ranges(void)
{
	unsigned long config = 0, dummy;
	
	if(use_intel())
		rdmsr(MSR_MTRRcap, config, dummy);
	else if (is_cpu(AMD))
		config =2 ;
	else if(is_cpu(CYRIX) || is_cpu(CENTAUR))
		config  = 8;
	
	num_var_ranges = config & 0xff;
}

static void __init init_table(void)
{
	int i, max;
	max = num_var_ranges;
	for(i = 0; i < max; i++)
		mtrr_usage_table[i] = 1;
}

struct set_mtrr_data {
	unsigned long smp_base;
	unsigned long smp_size;
	unsigned int smp_reg;
	mttr_type smp_type;
};

/** 
** mtrr_rendezvous_handler - Work done in the synchronization handler. Executed
** by all the CPUs.
** @info:pointer to mtrr configuration data 
**
** Returns nothing.
**/
static int mtrr_rendezvous_handler(void *info)
{
	struct set_mtrr_data *data = info;
	/**
	** We use this same function to initialize the mtrrs during boot,
	** resume, runtime cpu online and on an explicit request to set a 
	** specific MTRR.
	**
	** During boot or suspend, the state of the boot cpu's mtrrs has been
	** saved, and we want to replicate that across all the cpus that come 
	** online (either at the end of boot or resume or during a runtime cpu 
	** online). If we're doing that, @reg is set to something special and on 
	** all the cpu's we do mtrr_if->set_all()(On the logical cpu that 
	** started the boot/resume sequence, this might be a duplicate 
	** set_all()).
	**/
	if( data->smp_reg != ~0U) {
		mtrr_if->set(data->smp_reg, data->smp_base,
			data->smp_size, data->smp_type);
	} else if (mtrr_aps_delayed_init || !cpu_online(smp_processor_id())) {
		
		mtrr_if->set_all();
	}
	
	return 0;
}

static inline int types_compatible(mtrr_type type1, mtrr_type type2)
{
	return type1 == MTRR_TYPE_UNCACHABLE ||
		type2 == MTRR_TYPE_UNCACHABLE ||
		(type1 == MTRR_TYPE_WRTHROUGH && type2 == MTRR_TYPE_WRBACK) ||
		(type1 == MTRR_TYPE_WRBACK && type2 == MTRR_TYPE_WRTHROUGH);
}

/**
** set_mtrr - update mtrrs on all processors
** @reg :  mtrr in question
** @base:  mtrr base 
** @size: mtrr size 
** @type: mtrr type
*
** This is kinda tricky, but fortunately, Intel spelled it out for us cleanly:
*
** 1.Queue work to do the following on all processors:



