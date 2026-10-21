obj-m +=rev-shell.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules KCFLAGS=-D__DISABLE_BTF__

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
