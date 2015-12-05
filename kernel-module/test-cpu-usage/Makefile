obj-m += cpu_usage.o 
cpu_usage-objs:= test_module_cpu.o

CURRENT_PATH        :=$(shell pwd)
LINUX_KERNEL        :=$(shell uname -r) 
LINUX_KERNEL_PATH   :=/usr/src/linux-headers-$(LINUX_KERNEL)

all:   
	make -C$(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules  
clean:   
	make -C$(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean 
