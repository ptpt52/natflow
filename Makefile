# build modules
#EXTRA_CFLAGS = -Wall
obj-m += natflow.o

natflow-y += natflow_main.o natflow_common.o natflow_l7.o natflow_dpi.o natflow_path.o natflow_user.o natflow_zone.o natflow_urllogger.o natflow_conntrack.o

EXTRA_CFLAGS += -Wall -Werror -Wno-stringop-overread

ifdef NO_DEBUG
EXTRA_CFLAGS += -Wno-unused -Os -DNO_DEBUG
endif

ccflags-y += $(EXTRA_CFLAGS)

# Keep individual L7 data-plane frames bounded.  The cumulative call-chain
# budget is reviewed separately with compiler-generated .su files.
CFLAGS_natflow_l7.o += -Werror=frame-larger-than=512
CFLAGS_natflow_dpi.o += -Werror=frame-larger-than=512
CFLAGS_natflow_urllogger.o += -Werror=frame-larger-than=512

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
