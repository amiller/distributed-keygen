for i in `cat used.txt`; do  host $i; done >> tmp
cat tmp | egrep '\b([0-9]*\.){3}([0-9]*)' | awk '{ split($(NF),fields," "); print ++count " " $4 " 9900 certs/" count ".pem";}' > contlist
