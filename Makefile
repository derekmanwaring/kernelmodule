obj-m := firewall.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -f *.mod.*
	rm -f *.o
