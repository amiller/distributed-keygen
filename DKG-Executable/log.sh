slice_name=`cat 'monitor.conf' | grep "slice_name" | awk '{ split($(NF),fields,  "=");print fields[2];}'`
cat contlist | awk '{ split($(NF),fields," ");print $2;}' > IP
mkdir $@
cnt=0
for i in `cat IP`
do
	echo "connecting to $i"
	let cnt=cnt+1
        scp -r $slice_name@$i:./message.log $@/message_$cnt.log&
        scp -r $slice_name@$i:./dkg*.log $@/dkg_$cnt.log&
        scp -r $slice_name@$i:./timeout.log $@/timeout_$cnt.log&
done
