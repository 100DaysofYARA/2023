#!/bin/awk -f 

# Count the number of times a string matches in YARA.
# https://gist.github.com/wxsBSD/4ec929a0eb07d8e3feeccc49e0d9aa2a

!/^0x/ {
  if (length(strings) > 0) {
    for (string in strings) {
      print string ": " strings[string];
    }
  }
  delete strings
  print;
}

/^0x/ {
  split($1, fields, ":");
  strings[fields[2]]++;
}

END {
  for (string in strings) {
    print string ": " strings[string];
  }
}
