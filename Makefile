# build modules
#EXTRA_CFLAGS = -Wall
obj-m += natflow.o

natflow-y += natflow_main.o natflow_common.o natflow_path.o natflow_user.o natflow_zone.o natflow_urllogger.o natflow_conntrack.o

EXTRA_CFLAGS += -Wall -Werror -Wno-stringop-overread

ifdef NO_DEBUG
EXTRA_CFLAGS += -Wno-unused -Os -DNO_DEBUG
endif

PWD ?= $(shell pwd)

ifndef KERNELRELEASE
KERNELRELEASE := $(shell uname -r)
endif
    
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
KMAKE := $(MAKE) -C $(KERNELDIR) M=$(PWD)

all: modules

modules:
	$(KMAKE) modules

modules_install:
	$(KMAKE) modules_install

install: modules_install
	depmod

modules_clean:
	$(KMAKE) clean

clean: modules_clean
