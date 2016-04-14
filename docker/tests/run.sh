#!/bin/sh
# Run through each tool's directory and run it's test script
# Assume any error code other than 0 means a failed test
cd /tmp/tests
for tool in *
do
    [ ! -e "$tool/test" ] && continue
    PWNLIB_NOTERM=1 $tool/test
    if [ $? -ne 0 ]
    then
        echo "$tool failed test"
        exit 255
    else
        echo "$tool successful"
    fi
done
exit 0
