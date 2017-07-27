# $@ -- target file, $^ -- all dependent files, $< -- the first dependent file
MK_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	SHUF_CMD = gshuf
	ZCAT_CMD = gzcat
	EXTENDED_REGEXP_FLAG = -E
else
	SHUF_CMD = shuf
	ZCAT_CMD = zcat
	EXTENDED_REGEXP_FLAG = -r
endif

# File filter used for selecting the NDT files we would like to process
# e.g. 2016/10/* selects all files from all days on Oct. 2016
SOURCE_DATE_FILTER := 2017/01/01

FIG_DIR := pdfs
TRACE_DIR := ndt-trace-data
PROCESS_TRACE_FILE = "$(MK_PATH)process-trace-file.sh"
DOWNLOAD_TRACE_FILE = "$(MK_PATH)download-trace-file.sh"

# Specify column indexes based on the given OUTPUT_FORMAT
COL_FILENAME = 2
COL_DATA_PACKETS = 2
COL_FIRST_BREAKDOWN = 8
COL_LAST_BREAKDOWN = 13
COL_OVERALL_DELAY = 8


default: flows.csv

.PHONY: clean-results clean-unfiltered clean-all pack-results
.PRECIOUS: ndt-files $(CSV_FILES)

EXECUTABLES = reordercap gsutil $(ZCAT_CMD) gzip bc sed $(SHUF_CMD)
K := $(foreach exec,$(EXECUTABLES), \
	$(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH. Please install $(exec)")))

plots:
	mkdir -p $(FIG_DIR)

traces:
	mkdir -p $(TRACE_DIR)

clean-all: clean-results clean-unfiltered
	rm -f *.gen.mk
	rm -f ndt-files*

clean-results:
	rm -f $(FIG_DIR)/*
	rm -f *.csv

clean-traces:
	rm -rf $(TRACE_DIR)/*

clean-unfiltered:
	rm -f *.csv.gz

# Generate the list of NDT files to process
ndt-files:
	gsutil ls gs://m-lab/ndt/$(SOURCE_DATE_FILTER)/*.tgz > $@

# Change the postfix of NDT file name from .tgz -> .csv.gz
ndt-files-no-path: ndt-files
	cat $< | sed -e 's#^.*/\([^/]*\)\.tgz$$#\1.csv.gz#' >> $@

trace.gen.mk: ndt-files
	echo "TRACE_FILES = \\" > $@
	cat $< | awk '{printf "%s \\\n", $$0}' >> $@
	echo >> $@

deps.gen.mk: ndt-files-no-path
	echo "CSV_FILES = \\" > $@
	cat $< | awk '{printf "%s \\\n", $$0}' >> $@
	echo >> $@

-include deps.gen.mk
-include trace.gen.mk

HC_CSV_FILES := $(addprefix hc-, $(CSV_FILES))

# Filter -- 
# Aggregate and keep high-correlation cases (which is not included in this test)

test-case:
	echo $(CSV_FILES) | sed 's#.gz##g'

policed-traces: $(TRACE_DIR)
	for file in $(CSV_FILES); do \
		tmp=`echo $$file | sed -e 's#^\(.*\)\.csv\.gz$$#\1.csv#'`; \
		echo $$tmp; \
		$(DOWNLOAD_TRACE_FILE) $$tmp; \
	done;

hc-%.csv.gz: %.csv.gz
	$(ZCAT_CMD) $^ | \
	awk -F ',' '{if ($$3 >= 0) print}' | \
	gzip > $@



$(CSV_FILES):
	echo $(@:.gz=)
	$(PROCESS_TRACE_FILE) $(@:.gz=)
	gzip $(@:.gz=)


rtt-general.csv:
	for file in $(CSV_FILES); do \
		tmp=`echo $$file | sed -e 's#^\(.*\)\.csv\.gz$$#\1.csv#'`; \
		echo $$tmp; \
		$(PROCESS_TRACE_FILE) $$tmp; \
		gzip $$tmp; \
	done;





# DOWNLOAD_TRACE_FILE: ./download-trace-file.sh
# The script is used to download ndt-files and filter out non-policed traces.
# All policed traces will be stored at POLICED_TRACE_DIR: ./ndt-trace-data

test-4: ndt-files ndt-trace-data 
	for f in `cat $<`; do \
		echo $$f; \
		($(DOWNLOAD_TRACE_FILE) $$f || echo $$f,ERROR); \
	done;
	echo "Finish!"


test-2.csv: ndt-files-no-path $(HC_CSV_FILES)
	rm -f $@
	for f in `cat $<`; do \
		echo hc-$$f; \
		($(ZCAT_CMD) hc-$$f || echo hc-$$f,ERROR) | \
		awk -F, '{if ($$14 == 1) print}'
	done
	echo "Succeed"

test-1.csv: ndt-files-no-path $(HC_CSV_FILES)
	rm -f $@
	for f in `cat $<`; do \
		echo hc-$$f; \
		$(ZCAT_CMD) hc-$$f | \
		awk -F, '{if ($$14 == 0) print}' | \
		gzip > $@
	done
	echo "Succeed"

test.csv: ndt-files-no-path
	echo $(MK_PATH)
	rm -f $@
	for f in `cat $<`; do \
		echo $$f; \
	done

flows.csv: ndt-files-no-path $(HC_CSV_FILES)
	echo $(MK_PATH)
	rm -f $@
	for f in `cat $<`;
		echo hc-$$f;
	done

# Combine all the input files and only select lines with at least 100 packets
flow.csv: ndt-files-no-path $(HC_CSV_FILES)
	rm -f $@
	for f in `cat $<`; do \
		echo hc-$$f; \
		$(ZCAT_CMD) hc-$$f | \
		awk -F, '{if ($$$(COL_DATA_PACKETS) >= 100) print}' >> $@; \
		echo hc-$$f;
	done

packet_nums.csv: ndt-files-no-path $(HC_CSV_FILES)
	rm -f $@
	for f in `cat $<`; do \
		echo hc-$$f; \
		$(ZCAT_CMD) hc-$$f | \
		awk -F, '{if ($$3 >= 100) print}' >> $@; \
	done



