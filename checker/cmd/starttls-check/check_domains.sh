#!/bin/bash

lines=""
while read line
do
    lines="${lines}\n${line}"
done

echo -e $lines | grep ",queued" | ./starttls-check -log "queued_check_results.json" | grep SUCCESS
