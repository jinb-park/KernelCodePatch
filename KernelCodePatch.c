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

/*
* Do not consider LPAE now
*/

#define SECTION_SHIFT	20
#define SECTION_SIZE	(1UL << SECTION_SHIFT)
#define SECTION_MASK	(~(SECTION_SIZE-1))

/*
#define PMD_SECT_AP_WRITE	( ((pmdval_t)1) << 10 )
#define PMD_SECT_APX	( ((pmdval_t)1) << 15 )	*/

typedef struct _SectionPerm {
	unsigned long start;
	unsigned long end;
	pmdval_t mask;
	pmdval_t prot;
	pmdval_t clear;
}SectionPerm;

SectionPerm roPerm;

void SectionUpdate(unsigned long addr, pmdval_t mask, pmdval_t prot) {
	struct mm_struct *mm;
	pmd_t *pmd;

	mm = current->active_mm;
	pmd = pmd_offset(pud_offset(pgd_offset(mm, addr), addr), addr);

	if (addr & SECTION_SIZE)
		pmd[1] = __pmd((pmd_val(pmd[1]) & mask) | prot);
	else
		pmd[0] = __pmd((pmd_val(pmd[0]) & mask) | prot);

	flush_pmd_entry(pmd);
	flush_tlb_all();
	//local_flush_tlb_kernel_range(addr, addr + SECTION_SIZE);
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
	pmd = pmd_offset(pud_offset(pgd_offset(mm, addr), addr), addr);

	for(addr = sp->start; addr < sp->end; addr += SECTION_SIZE) {
		if (addr & SECTION_SIZE)
			pmdIdx = 1;
		else
			pmdIdx = 0;

		pmdVal = pmd_val(pmd[pmdIdx]);
		printk( "Addr : [%08x], PMD Val : [%08x], APX : [%d], AP(r) : [%d], AP(w) : [%d]\n", 
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
* Test Patch Function (system call table patch)
*/
unsigned long *syscall = NULL;
int isHookSucceed = 0;

asmlinkage int (*real_sysinfo)(struct sysinfo* info);
asmlinkage int custom_sysinfo(struct sysinfo* info) {
	return real_sysinfo(info);
}

void HookSCT(void) {
	syscall = (unsigned long*)kallsyms_lookup_name("sys_call_table");

	printk("[KCP] syscall table : %08x\n", syscall);

	real_sysinfo = (void*)*(syscall + __NR_sysinfo);
	*(syscall + __NR_sysinfo) = (unsigned long)custom_sysinfo;

	printk("[KCP] Hook Success\n");
	isHookSucceed = 1;
}
void RestoreSCT(void) {
	if(isHookSucceed && syscall) {
		*(syscall + __NR_sysinfo) = (unsigned long)real_sysinfo;
	}
}

/*
* stop_machine environment
* [ToDo] disable preemption
*/
int __PatchCode(void *data) {
	GetSectionPerms(&roPerm);

	SetKernelTextRW(&roPerm);
	HookSCT();

	GetSectionPerms(&roPerm);
	return 0;
}

void PatchCodeUnderStopMachine(void) {
	stop_machine(__PatchCode, NULL, NULL);
}
void PatchCode(void) {
	HookSCT();
}


int __init KernelCodePatchInit(void) {
	InitSectionPerms(&roPerm);
	
	PatchCodeUnderStopMachine();
	
	return 0;
}

void __exit KernelCodePatchExit(void) {
	return;
}

module_init(KernelCodePatchInit);
module_exit(KernelCodePatchExit);
MODULE_LICENSE("GPL");