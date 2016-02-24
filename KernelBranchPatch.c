#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/current.h>
#include <asm/tlbflush.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/preempt.h>
#include <asm/string.h>
#include <linux/highmem.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/delay.h>
#include <linux/stop_machine.h>
#include <asm/page.h>

#include "SectionUpdate.h"
#include "ARMBranchPatch.h"

unsigned long do_filp_open_addr;	// func
unsigned long path_openat_addr;  // from
								// to - hook_path_openat
unsigned long do_filp_open_size = 80;

void hook_path_openat(void) {
	return;
}

void BranchPatchFunc(void) {
	ARM_BranchPatch(do_filp_open_addr, do_filp_open_size, path_openat_addr, hook_path_openat);
}

int __init KernelBranchPatchInit(void) {
	do_filp_open_addr = kallsyms_lookup_name("do_filp_open");
	path_openat_addr = kallsyms_lookup_name("path_openat");

	PatchCode(BranchPatchFunc);
	return 0;
}

void __exit KernelBranchPatchExit(void) {
	return;
}

module_init(KernelBranchPatchInit);
module_exit(KernelBranchPatchExit);
MODULE_LICENSE("GPL");
