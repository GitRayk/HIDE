obj-m := extended.o
extended-objs := main.o output.o input.o extended_header.o kern_aes.o kern_ioctl.o

EXTRA_CFLAGS += -Wall -I$(src)/include/

all:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) modules

clean:	
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) clean
