#!/usr/bin/awk -f

# Consolidate all YARA rule matches for a given file into a single line.
# https://gist.github.com/wxsBSD/3e9452c3699bf68ff2e83a5d6a521801

{
  if ($2 in files) {
    files[$2 ] = files[$2] "," $1
  } else {
    files[$2] = $1
  }
}

END {
  for (file in files) {
    print file "\t" files[file]
  }
}
