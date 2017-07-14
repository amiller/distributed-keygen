slice_name=`cat 'monitor.conf' | grep "slice_name" | awk '{ split($(NF),fields,  "=");print fields[2];}'`
version_chars=`cat 'monitor.conf' | grep "version_chars" | awk '{ split($(NF),fields,  "=");print fields[2];}'`
for i in `cat used.txt`; do ssh $slice_name@$i "killall node$version_chars > /dev/null; rm message*.log > /dev/null; rm dkg*.log > /dev/null"& done
