#!/bin/bash
set -e

UNAME_S=$(uname -s)
if [ "$UNAME_S" == "Darwin" ]; then
	ZCAT_CMD=gzcat
	READLINK=greadlink
else
	ZCAT_CMD=zcat
	READLINK=readlink
fi

CSV_GZ_FILE=$1
#$ZCAT_CMD $CSV_GZ_FILE | awk -F, '{if ($14 == 0) {print $2;}}'


for f in "`$ZCAT_CMD $CSV_GZ_FILE | awk -F, '{if ($14 == 0) {print $2;}}'`"
do
	echo $f
done