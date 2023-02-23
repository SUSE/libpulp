#!/bin/bash

# Look for the number of symbols and how many symbols will need to be read to
# decide if a library is livepatchable or not in /usr/lib64 to collect
# statistics.

get_first_function_symbol()
{
  local realfile=$(readlink -f $1)
  local symbol=$(readelf -D -sW $realfile | grep -E "FUNC[ ]*GLOBAL[ ]*DEFAULT[ ]*[0-9]+" | head -n 1 | awk '{ print substr($1, 1, length($1)-1) }')
  local num_symbols=$(readelf -D -sW $realfile | tail -n 1 | awk '{ print substr($1, 1, length($1)-1) }')

  echo "Analyzing $realfile"
  echo "$realfile, $symbol", $num_symbols >> output.csv
}

rm -f output.csv
for so in $(find "/usr/lib64/" -name "*.so"); do
  get_first_function_symbol $so
done

sort -u output.csv -o output.csv
