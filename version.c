#include <generated/compile.h>
#include <linux/module.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <generated/utsrelese.h>
#include <linux/version.h>
#include <linux/proc_ns.h>

#ifndef CONFIG_KALLSYMS
#define version(a) Version_##a
#define version_string(a) version(a)

extern int version_string(LINUX_VERSION_CODE);
int version_string(LINUX_VERSION_CODE);
#endif

struct uts_namespace init_uts_ns = {
	.kref = KREF_INIT(2),
	.name = {
		.sysname = UTS_SYSNAME,
		.nodename = UTS_NODENAME,
		.release = UTS_RELEASE,
		.version = UTS_VERSION,
		.machine = UTS_MACHINE,
		.domainname = UTS_DOMAINNAME,
	},
	.user_ns = &init_user_ns,
	.ns.inum = PROC_UTS_INIT_INO,
	
#ifdef CONFIG_UTS_NS
	.ns.ops = &utsns_operations,
#endif

};
EXPORT_SYSBOL_GPL(init_uts_ns);

/** FIXED STRING! Don't touch ! **/
const char linux_banner[] = 
	"Linux version" UTS_RELEASE "(" LINUX_COMPILE_BY "@"
	LINUX_COMPILE_HOST")("LINUX_COMPILER")" UTS_VERSION"\n";
	
const char linux_proc_banner[] = 
	"%s version %s"
	"(" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ")"
	"(" LINUX_COMPILER") %s\n";







































