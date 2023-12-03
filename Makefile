obj-m := extended.o
extended-objs := main.o output.o input.o extended_header.o kern_aes.o kern_ioctl.o kern_hash.o hash_table.o

EXTRA_CFLAGS += -Wall -I$(src)/include/

all:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) modules

clean:	
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) clean

# 启动 app 之前要使用命令 sudo mknod /dev/labelCmd c 168 0
app:
	gcc app_a.c -o app_a -I./include
	gcc app_b.c -o app_b -I./include