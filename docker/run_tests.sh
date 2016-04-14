#!/bin/sh
docker run -v /Users/coryduplantis/workspace/epictreasure/docker/tests:/tmp/tests --rm ctfhacker/epictreasure /tmp/tests/run.sh
if [ $? -eq 0 ]
then
    docker push ctfhacker/epictreasure
fi
