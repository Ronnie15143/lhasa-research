#!/system/bin/sh
# avc_probe.sh - use logcat's avc denials as a permission oracle.
#
# Until now every privileged write was fire-and-forget: code 6/7 return 0
# whether or not the write landed. Android logs SELinux denials to logcat
# (auditd + the offending domain), so a denied write leaves
#   avc: denied { write } ... tcontext=u:object_r:<target label> tclass=blk_file
# which makes the question testable instead of guessable.
#
# Step 1 validates the oracle on a path already known to be denied.

CL="CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog miui.mqsas.IMQSNative"
MARK="AVCPROBE$$"

check() {
  # wait a moment for auditd to flush, then look for denials from this probe
  sleep 1
  echo "    avc lines mentioning '$1':"
  logcat -d -b all 2>/dev/null | grep "avc:" | grep -i "$1" | tail -3 | sed 's/^/      /'
}

echo "=== step 1: validate oracle on a path known to be denied (/data/local/tmp) ==="
eval $CL 7 /data/local/tmp/$MARK probe >/dev/null 2>&1
check "local_tmp"
check "shell_data_file"

echo
echo "=== step 2: same probe against misc ==="
eval $CL 7 /dev/block/by-name/misc K >/dev/null 2>&1
check "misc_block_device"
check "misc"

echo
echo "=== step 3: android_esp_b (inactive slot, unbootable) ==="
eval $CL 7 /dev/block/by-name/android_esp_b K >/dev/null 2>&1
check "android_esp_block_device"
check "android_esp"

echo
echo "=== step 4: a path we know IS writable (/data/anr) as a negative control ==="
eval $CL 7 /data/anr/$MARK probe0 >/dev/null 2>&1
check "anr_data_file"
echo "    file present: $(ls -l /data/anr/$MARK 2>&1)"
