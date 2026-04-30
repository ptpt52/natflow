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

check-kerneldir:
	@if [ ! -d "$(KERNELDIR)" ]; then \
		echo "ERROR: kernel build dir not found: $(KERNELDIR)"; \
		echo "Hint: install headers for $(KERNELRELEASE), or pass KERNELDIR=/path/to/linux/build"; \
		exit 1; \
	fi

all: modules

modules: check-kerneldir
	$(KMAKE) modules

modules_install: check-kerneldir
	$(KMAKE) modules_install

install: modules_install
	depmod

modules_clean:
	@if [ -d "$(KERNELDIR)" ]; then $(KMAKE) clean; else echo "Skip clean: $(KERNELDIR) not found"; fi

clean: modules_clean
