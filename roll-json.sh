new_list_data_full=$(wget -q -O - localhost:8080/auth/list?filename=$2)
timestamp_data=$(echo "$new_list_data_full" | head -n 6 | tail -n 2 | cut -c 3- )
old_list_data=$(cat $1 | head -n -3 | tail -n +4)
new_list_data=$(echo "$new_list_data_full" | tail -n +12 | head -n -3 | cut -c 3-)

echo "{" > tmp.json
echo "$timestamp_data" >> tmp.json # timestamp from new JSON
echo "$old_list_data" >> tmp.json  # bulk of old list
echo "    }," >> tmp.json
echo "$new_list_data" >> tmp.json  # bulk of new list
tail -n 2 $1 >> tmp.json           # closing braces

mv tmp.json $1
