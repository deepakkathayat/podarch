#obj stands for object
#m stands for module/driver
#this is the list of modules that the kernel building system needs to build
obj-m += pod_kret.o
KDIR := /home/vichu/working3/linux-4.2/
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -f *.mod.c *.ko *.o *.order *.symvers
	rm -rf .tmp_versions/
	rm -f .*.o.cmd
	rm -f .*.ko.cmd
