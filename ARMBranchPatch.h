#ifndef _ARM_BRANCH_PATCH_H
#define _ARM_BRANCH_PATCH_H

void ARM_BranchPatch(unsigned long *func, unsigned long size, unsigned long *from, unsigned long *to);

#endif