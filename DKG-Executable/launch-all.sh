slice_name=`cat 'monitor.conf' | grep "slice_name" | awk '{ split($(NF),fields,"=");print fields[2];}'`
cat contlist | awk '{ split($(NF),fields," ");print $2;}' > IP
cnt=0
for i in `cat IP`
do  
  let cnt=cnt+1
  echo "ssh -n $slice_name@$i ./node_8_0 9900 certs/$cnt.pem certs/$cnt-key.pem contlist 0 0 0$@&"
  ssh -n $slice_name@$i ./node_8_0 9900 certs/$cnt.pem certs/$cnt-key.pem contlist 0 0 0$@&
done
