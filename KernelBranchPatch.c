#include <linux/module.h>
#include <linux/namei.h>
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

unsigned long prepare_binprm_addr;	// func
unsigned long kernel_read_addr;  // from
								// to - hook_path_openat
unsigned long prepare_binprm_size = 304;

/*
* Do not consider LPAE now
*/

#define SECTION_SHIFT	20
#define SECTION_SIZE	(1UL << SECTION_SHIFT)
#define SECTION_MASK	(~(SECTION_SIZE-1))

/*
#define PMD_SECT_AP_WRITE	( ((pmdval_t)1) << 10 )
#define PMD_SECT_APX	( ((pmdval_t)1) << 15 )	*/


/*
 *******************************************
 ************* Section Update ************
 *******************************************
*/
typedef struct _SectionPerm {
	unsigned long start;
	unsigned long end;
	pmdval_t mask;
	pmdval_t prot;
	pmdval_t clear;
}SectionPerm;

SectionPerm roPerm;
int roPermIntialized = 0;

void SectionUpdate(unsigned long addr, pmdval_t mask, pmdval_t prot) {
	struct mm_struct *mm;
	pmd_t *pmd;

	mm = current->active_mm;
	pmd = pmd_offset(pud_offset(pgd_offset(mm, addr), addr), addr);

	if (addr & SECTION_SIZE) {
		pmd[1] = __pmd((pmd_val(pmd[1]) & mask) | prot);
	}
	else {
		pmd[0] = __pmd((pmd_val(pmd[0]) & mask) | prot);
	}

	flush_pmd_entry(pmd);
	//flush_tlb_all();
	local_flush_tlb_kernel_range(addr, addr + SECTION_SIZE);
	flush_icache_range(addr, addr + SECTION_SIZE);
}

void SetSectionPerms(SectionPerm *sp, pmdval_t prot) {
	unsigned int i;
	unsigned long addr;

	if( sp->start == 0 || sp->end == 0) {
		printk("[KCP] SectionPerm address is NULL\n");
		return;
	}

	for(addr = sp->start; addr < sp->end; addr += SECTION_SIZE) {
		SectionUpdate(addr, sp->mask, prot);
	}
	printk("[KCP] SetSectionPerms end\n");
}
void GetSectionPerms(SectionPerm *sp) {
	unsigned int i, pmdIdx;
	unsigned long addr;
	struct mm_struct *mm;
	pmdval_t pmdVal;
	pmd_t *pmd;

	if( sp->start == 0 || sp->end == 0) {
		printk("[KCP] SectionPerm address is NULL\n");
		return;
	}

	mm = current->active_mm;
	for(addr = sp->start; addr < sp->end; addr += SECTION_SIZE) {
		pmd = pmd_offset(pud_offset(pgd_offset(mm, addr), addr), addr);

		if (addr & SECTION_SIZE)
			pmdIdx = 1;
		else
			pmdIdx = 0;

		pmdVal = pmd_val(pmd[pmdIdx]);
		printk( "[KCP] Addr : [%08x], PMD Val : [%08x], APX : [%d], AP(r) : [%d], AP(w) : [%d]\n", 
					addr, pmdVal, 
					!!(pmdVal & PMD_SECT_APX), 
					!!(pmdVal & PMD_SECT_AP_READ),
					!!(pmdVal & PMD_SECT_AP_WRITE) );
	}
	printk("[KCP] GetSectionPerms end\n");
}
void InitSectionPerms(SectionPerm *sp) {
	unsigned long mask = 0;

	if(!sp)
		return;

	sp->start = kallsyms_lookup_name("_stext");
	sp->end = kallsyms_lookup_name("__init_begin");
	if(sp->end == 0) {
		sp->end = kallsyms_lookup_name("_etext");
	}

	if( !IS_ALIGNED(sp->start, SECTION_SIZE) || !IS_ALIGNED(sp->end, SECTION_SIZE) ) {
		// Correction
		mask = (SECTION_SIZE - 1);
		mask = ~(mask);

		sp->start = (sp->start & mask);
		sp->end = (sp->end & mask);

		printk("[KCP] correction of addr : [%08x] ~ [%08x]\n", sp->start, sp->end);
	}
	
	sp->mask = ~(PMD_SECT_APX | PMD_SECT_AP_WRITE);
	sp->prot = PMD_SECT_APX | PMD_SECT_AP_WRITE;
	sp->clear = PMD_SECT_AP_WRITE;

	roPermIntialized = 1;
	printk("[KCP] %08x, %08x\n", sp->start, sp->end);
}

void SetKernelTextRO(SectionPerm *sp) {
	if(!sp)
		return;

	SetSectionPerms(sp, sp->prot);
}
void SetKernelTextRW(SectionPerm *sp) {
	if(!sp)
		return;

	SetSectionPerms(sp, sp->clear);
}

/*
 *******************************************
 ************* ARM Branch Patch **********
 *******************************************
*/
 unsigned long ARM_GenBranch(unsigned long pc, unsigned long addr, int link) {
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

				printk("[KCP] pc : [%08x]\n", pc);
				printk("[KCP] dest : [%08x], orig-inst : [%08x], patched-inst : [%08x]\n", (unsigned long)to, inst, finalInst);

				/* Patch */
				*(func + i) = finalInst;
				flush_icache_range((unsigned long)(func + i), (unsigned long)(func + i + 1));
			}
		}
		i++;
	}
}

/*
* PatchCode
* stop_machine environment
*/
int __PatchCode(void *data) {
	void (*patchFunc)(void) = data;

	preempt_disable();
	GetSectionPerms(&roPerm);

	SetKernelTextRW(&roPerm);
	patchFunc();

	GetSectionPerms(&roPerm);
	preempt_enable();
	return 0;
}

void PatchCode(void (*patchFunc)(void)) {
	stop_machine(__PatchCode, (void*)patchFunc, NULL);
}

int (*orig_kernel_read)(struct file *file, loff_t offset, char *addr, unsigned long count);
void hook_kernel_read(struct file *file, loff_t offset, char *addr, unsigned long count) {
	printk("[KCP] hook_kernel_read\n");
	return orig_kernel_read(file, offset, addr, count);
}

void BranchPatchFunc(void) {
	ARM_BranchPatch(prepare_binprm_addr, prepare_binprm_size, kernel_read_addr, hook_kernel_read);
}
void RestorePatchFunc(void) {
	ARM_BranchPatch(prepare_binprm_addr, prepare_binprm_size, hook_kernel_read, kernel_read_addr);
}

int __init KernelBranchPatchInit(void) {
	prepare_binprm_addr = kallsyms_lookup_name("prepare_binprm");
	kernel_read_addr = kallsyms_lookup_name("kernel_read");
	orig_kernel_read = kernel_read_addr;

	InitSectionPerms(&roPerm);
	PatchCode(BranchPatchFunc);
	return 0;
}

void __exit KernelBranchPatchExit(void) {
	PatchCode(RestorePatchFunc);
	return;
}

module_init(KernelBranchPatchInit);
module_exit(KernelBranchPatchExit);
MODULE_LICENSE("GPL");
