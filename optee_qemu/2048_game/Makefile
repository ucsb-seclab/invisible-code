CROSS_COMPILE = $(HOST_CROSS_COMPILE)

DRM = -Wall -I./include -fomit-frame-pointer

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

export OBJCOPY
export CC

all:
	$(CC) -c 2048.c -o 2048.o $(DRM)
	$(CC) 2048.o -o 2048
	./gen_random_data_elfs.sh

clean:
	rm -f 2048

