#!/bin/sh
CURDIR=$(pwd)
DEVICE_PROTO="$CURDIR/../device-protocol"
DEVICE_PROTO_VERSION="v5.0.0"

if [ ! -d $DEVICE_PROTO ];
then
    git clone --branch $DEVICE_PROTO_VERSION --depth 1 https://github.com/keepkey/$DEVICE_PROTO.git $DEVICE_PROTO
fi

cd $DEVICE_PROTO

echo "Building with protoc version: $(protoc --version)"
for i in messages types exchange ; do
    protoc --python_out=$CURDIR/keepkeylib/ -I/usr/include -I. $i.proto
    sed -i -Ee 's/^import ([^.]+_pb2)/from . import \1/' $CURDIR/keepkeylib/"$i"_pb2.py
done

sed -i 's/5000\([2-5]\)/6000\1/g' $CURDIR/keepkeylib/types_pb2.py
