#!/bin/bash
set -e

UNAME_S=$(uname -s)
if ["$UNAME_S" == "Darwin"]; then
	READLINK=greadlink
else
	READLINK=readlink
fi

PROCESS_PCAP="`READLINK -f $(dirname \"${BASH_SOURCE[0]}\")/exp_process_1.py`"
T_PROCESS_PCAP="`READLINK -f $(dirname \"${BASH_SOURCE[0]}\")/../policing/policing-detection/process_pcap.py`"

CSV_FILE=$1
echo $CSV_FILE
GS_FILE=`echo $CSV_FILE | sed -e 's#^\(\(....\)\(..\)\(..\).*\)\.csv$#gs://m-lab/ndt/\2/\3/\4/\1.tgz#'`

echo "Processing $GS_FILE"

TRACE_DIR=`mktemp -d /tmp/tmp.XXXXXX`

gsutil cp $GS_FILE $TRACE_DIR

tar xzf $TRACE_DIR/*.tgz --strip=3 -C $TRACE_DIR
rm -f $TRACE_DIR/*.c2s_ndttrace $TRACE_DIR/*.tgz

# Check if there are any files to process.
if ls $TRACE_DIR/*ndttrace >/dev/null 2>&1; then
	cd $TRACE_DIR
	for TRACE in `ls -1 *ndttrace`; do
    if file $TRACE | grep 'gzip compressed data' > /dev/null; then
      mv $TRACE $TRACE.gz
      gunzip $TRACE.gz
    fi
    ulimit -Sv 100000000
    echo "Trace: $TRACE_DIR/$TRACE"
    mv $TRACE $TRACE.bkp
    reordercap $TRACE.bkp $TRACE || continue
    (echo "$(python $PROCESS_PCAP $TRACE)" || echo $TRACE,ERROR) | sed -e "s#^#$GS_FILE,#" >> result.csv
  done
  cd -
  
  cp $TRACE_DIR/result.csv $CSV_FILE
else
	echo "$GS_FILE has no trace data."
	touch $CSV_FILE
fi

rm -rf $TRACE_DIR
