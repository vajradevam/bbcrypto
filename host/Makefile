obj-m := bbcrypto.o
KDIR ?= /lib/modules/$(shell uname -r)/build
ccflags-y := -I$(src)/..

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
