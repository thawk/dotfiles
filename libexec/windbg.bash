subsegment() {
  rtlpLFHKey=$1
  heap=$2
  subsegmentcode=$3
  address=$4
  echo "obase=16; ibase=16; $(((((address - 8)/8) ^ heap ^ heap ^ subsegmentcode) + 4))" | bc
}

