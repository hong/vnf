# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSBULL_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

CFLAGS += $(DEBFLAGS)
CFLAGS += -I..

PWD := $(shell pwd)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
obj-m := vnf.o

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
  include .depend
endif

clean:
	rm -f *.ko
	rm -f *.o
	rm -f .*.mod.c
	rm -f *.mod.c
	rm -f .*.cmd
	rm -rf .tmp_versions
	rm -f *.symvers
	rm -f .depend
	rm -f *~
