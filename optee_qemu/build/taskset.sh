#!/usr/bin/env bash
pid=`pgrep qemu-system`
taskset -cp 0 ${pid}
taskset -cp 0 $(python -c "print $pid+1,")
taskset -cp 1 $(python -c "print $pid+2,")
