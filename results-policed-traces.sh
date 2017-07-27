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

POLICED_TRACE_DIR="`$READLINK -f $(dirname ${BASH_SOURCE[0]})/ndt-trace-data`"
PROCESS_PCAP="`$READLINK -f $(dirname \"${BASH_SOURCE[0]}\")/exp_process_1.py`"


rm -f $POLICED_TRACE_DIR/*.csv $POLICED_TRACE_DIR/*.csv.gz

if ls $POLICED_TRACE_DIR >/dev/null 2>&1; then
	cd $POLICED_TRACE_DIR

	for csv_file in `ls ./`;
	do
		echo "Processing trace: $csv_file"
		(echo "$(python $PROCESS_PCAP $csv_file)" || echo $csv_file,ERROR) >> results.csv
	done
	cd -

	cp $POLICED_TRACE_DIR/results.csv ./results.csv
else
	echo "No trace to be processed"
	touch ./results.csv
fi


#cd $POLICED_TRACE_DIR
#ls ./results.csv
#gzip ./results.csv
#$ZCAT_CMD ./results.csv.gz | awk -F, '{if ($1 == "No Error" && &9 == 4) print}' >> $@; 
#$ZCAT_CMD ./results.csv.gz | awk -F, 'BEGIN {count = 0} {if ($9 == 1) count++} END {print count}'
#cd -
