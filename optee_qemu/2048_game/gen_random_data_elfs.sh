#!/usr/bin/env bash
# this script will use objcopy to create sections containing random data
# that will be used in order to benchmark data map fwd with different memory map size

for s in `seq 5 5 200`; do
	rm -f /tmp/randdata_2048 /tmp/randdata_2048.o
	dd if=/dev/urandom of=/tmp/randdata_2048 bs=1024 count=`python -c "print ${s}*1024"` # 5*1024
	$(${OBJCOPY} -Ibinary -Oelf32-littlearm -Barm /tmp/randdata_2048 /tmp/randdata_2048.o)
	$(${CC} ./2048.o /tmp/randdata_2048.o -o 2048_${s})
done;
