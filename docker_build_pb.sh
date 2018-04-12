#!/bin/bash



IMAGETAG=kktech/firmware:v3-beta

docker pull $IMAGETAG

docker run -it \
    -v $(pwd):/root/python-keepkey \
    -v $(pwd)/../device-protocol:/root/device-protocol \
    -w /root/python-keepkey \
    $IMAGETAG \
    ./build_pb.sh

cd keepkeylib && python flash_hash.py && cd ..
python2 setup.py install; 
python3 setup.py install;

