obj-m += redirect.o 
redirect-objs:= network_control.o

CURRENT_PATH        :=$(shell pwd)
LINUX_KERNEL        :=$(shell uname -r) 
LINUX_KERNEL_PATH   :=/usr/src/linux-headers-$(LINUX_KERNEL)

all:   
	make -C$(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules  
clean:   
	make -C$(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean 
