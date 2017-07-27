#!/bin/bash
set -e

UNAME_S=$(uname -s)
if [ "$UNAME_S" == "Darwin" ]; then
	READLINK=greadlink
	MKTEMP=gmktemp
else
	READLINK=readlink
	MKTEMP=mktemp
fi

CSV_FILE=$1
GS_FILE=`echo $CSV_FILE | sed -e 's#^\(\(....\)\(..\)\(..\).*\)\.csv$#gs://m-lab/ndt/\2/\3/\4/\1.tgz#'`

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR=`$MKTEMP -d /tmp/tmp.XXXXXX
gsutil cp $GS_FILE $TEMP_DIR

tar xzf $TEMP_DIR/*.tgz --strip=3 -c $TEMP_DIR
if ls $TEMP_DIR/$TRACE_FILE > /dev/null 2>&1; then
	cd $TEMP_DIR
	if file $TRACE_FILE | grep 'gzip compressed data' > /dev/null; then
		mv $TRACE_FILE ${TRACE_FILE}.gz
		gunzip ${TRACE_FILE}.gz
	fi
	cd -
	mv $TEMP_DIR/$TRACE_FILE $TARGET_FILE
	echo "Extracted $TRACE_FILE, and saved as $TARGET_FILE"
else
	echo "$TRACE_FILE does not exist in Archive $GS_FILE"
fi
rm -rf $TEMP_DIR