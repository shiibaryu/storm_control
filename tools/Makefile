CC = gcc
INCLUDE := -I../include/ -I../iproute2-4.19.0/include/
obj-m := libnetlink.o libgenl.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
