slice_name=`cat 'monitor.conf' | grep "slice_name" | awk '{ split($(NF),fields,  "=");print fields[2];}'`
cat contlist | awk '{ split($(NF),fields," ");print $2;}' > IP
for i in `cat IP`
do
	echo "connecting to $i"
	scp -r $@ $slice_name@$i:. > /dev/null&
done
