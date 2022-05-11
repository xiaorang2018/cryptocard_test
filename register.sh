#!/bin/bash


CMD=$2
#CMD="/usr/local/dms/bin/pcie_server &"
#CMD="do"

while read line
do
            echo $line
                if [ "$line" == "$CMD" ]; then
                        echo "[Register start up Server INFO]: there is command already in file"
                        echo "[Register start up Server INFO]: command = $CMD"
                        echo "[Register start up Server INFO]: file    = $1"
                        exit
                fi
done < $1

echo "$CMD" >> $1
echo "[Register start up Server SUCCESS]: insert success command in file"
echo "[Register start up Server SUCCESS]: command = $CMD"
echo "[Register start up Server SUCCESS]: file    = $1"

