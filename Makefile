PWD := $(shell pwd)
KERNEL_DIR := /lib/modules/`uname -r`/build
obj-m := vnf.o

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
	
clean:
	rm -f *.ko
	rm -f *.o
	rm -f .*.mod.c
	rm -f *.mod.c
	rm -f .*.cmd
	rm -rf .tmp_versions
	rm -f *.symvers
	rm -f *~
