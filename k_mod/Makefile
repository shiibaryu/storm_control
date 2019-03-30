obj-m := storm_control.o

THIS_DIR := $(shell pwd)

.phony: all
all: storm_control.ko

storm_control.ko: $(KOBJS) Makefile
	$(MAKE) -C $(KERNEL_DIR) M=$(THIS_DIR) modules c=2

.phony: install
install:
	$(MAKE) -C $(KERNEL_DIR) INSTALL_MOD_PATH=$(rootfs) M=$(THIS_DIR) -e modules_install

.phony: clean
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(THIS_DIR) clean
