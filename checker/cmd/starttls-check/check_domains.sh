#!/bin/bash

domains_file=$(mktemp)
while read line
do
    echo $line >> "${domains_file}"
done

./starttls-check -log "queued_check_results.json" -csv "${domains_file}"
rm ${domains_file}
