#!/system/bin/sh
# Freeze tracing, snapshot the text trace, then drain each per-CPU raw buffer.
# Both views then cover the SAME record window, so records can be paired by
# (cpu, common_pid, event_pid).
#
# NOTE: the sched_blocked_reason enable resets to 0 on every boot, so it has to
# be re-armed here or the capture comes back empty.
T=/sys/kernel/tracing
OUT=/data/local/tmp/pair

mkdir -p $OUT
rm -f $OUT/*

echo 0 > $T/tracing_on
echo > $T/trace
echo 1 > $T/events/sched/sched_blocked_reason/enable
echo 1 > $T/tracing_on
sleep 3
echo 0 > $T/tracing_on

cat $T/trace > $OUT/text.txt

NCPU=$(nproc)
i=0
while [ $i -lt $NCPU ]; do
  timeout 1 dd if=$T/per_cpu/cpu$i/trace_pipe_raw of=$OUT/raw_$i.bin bs=4096 count=400 2>/dev/null
  i=$((i+1))
done

echo "ncpu=$NCPU text=$(wc -c < $OUT/text.txt) bytes"
