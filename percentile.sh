#!/bin/bash
set -e


gzcat ./results-dev-size-1.csv.gz | \
awk -F: 'BEGIN {count = 0;} {if ($11 >= $12) count++} END {print count}'


gzcat ./results.csv.gz | awk -F: 'BEGIN {count = 0;} {if ($6==0) {print $1; count = count + 1;} END{print count}'