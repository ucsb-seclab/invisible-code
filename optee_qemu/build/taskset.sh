#!/usr/bin/env bash
pids=`ps -e -T | grep qemu-system-arm | cut -d' ' -f2`

cpu=0
for pid in $pids; do
    echo $cpu $pid
    taskset -cp $cpu ${pid}
    renice -20 $pid
    cpu=$((cpu+1))
done;
