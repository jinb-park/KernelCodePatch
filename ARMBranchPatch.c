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

unsigned long ARM_GenBranch(unsigned long pc, unsigned long addr, int link)
{
	unsigned long opcode = 0xea000000;
	long offset;

	if (link)
		opcode |= 1 << 24;

	offset = (long)addr - (long)(pc + 8);
	if (offset < -33554432 || offset > 33554428) {
		return 0;
	}

	offset = (offset >> 2) & 0x00ffffff;

	return opcode | offset;
}

/*
 * Replace (bl from) with (bl to) in func
*/
void ARM_BranchPatch(unsigned long *func, unsigned long size, unsigned long *from, unsigned long *to) {
	unsigned long i = 0;
	unsigned long inst = 0x00;
	unsigned long fromInst = 0x00;
	unsigned long *dest = 0x00;
	unsigned long pc = 0x00;
	char *ptr = &inst;

	unsigned long finalInst = 0x00;	// final instruction to be patched
	unsigned long remainSize = size;

	while(1) {
		if( remainSize >= sizeof(unsigned long) ) {
			remainSize -= sizeof(unsigned long);
		}else {
			break;
		}

		inst = *(func + i);
		
		if( ptr[3] == 0xeb) {
			pc = (unsigned long)(func + i);
			fromInst = ARM_GenBranch(pc, from, 1);

			if(inst == fromInst) {
				finalInst = ARM_GenBranch(pc, to, 1);

				printk("[KCP] dest : [%08x], orig-inst : [%08x], patched-inst : [%08x]\n", (unsigned long)to, inst, finalInst);

				/* Patch */
				//*(func + i) = finalInst;
			}
		}
		i++;
	}
}
