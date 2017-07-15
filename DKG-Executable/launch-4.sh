#!/bin/bash

function launch () {
    port=$1
    id=$2
    ./node_8_0 $port certs/$id.pem certs/$id-key.pem contlist 0 0 0
}

for x in `seq 1 4`
do
    rm -r node$x
    mkdir node$x
    ln -s $PWD/certs node$x/
    ln -s $PWD/system.param node$x/
    ln -s $PWD/pairing.param node$x/
done

tmux new-session    "cd node1; ../node_8_0 9001 ../certs/1.pem ../certs/1-key.pem ../contlist 0 0 0; bash" \;  \
     splitw -h -p 67 "cd node2; ../node_8_0 9002 ../certs/2.pem ../certs/2-key.pem ../contlist 0 0 0; bash" \;  \
     splitw -h -p 50 'tail -F node1/message.log; bash' \;  \
     splitw -v -p 50 'tail -F node2/message.log; bash' \;  \
     selectp -t 0 \; \
     splitw -v -p 50 "cd node3; ../node_8_0 9003 ../certs/3.pem ../certs/3-key.pem ../contlist 0 0 0; bash" \;  \
     selectp -t 2\; \
     splitw -v -p 50 "cd node4; ../node_8_0 9004 ../certs/4.pem ../certs/4-key.pem ../contlist 0 0 0; bash"
