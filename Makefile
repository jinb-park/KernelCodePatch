obj-m := KernelBranchPatch.o

KernelBranchPatch-objs := SectionUpdate.o ARMBranchPatch.o

default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
	#make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod *.symvers *.order *.mod.c
	#make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
