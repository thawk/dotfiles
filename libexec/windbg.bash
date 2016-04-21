read_input() {
    ret=$2
    if [ -z "$ret" ]; then
        read -p "$1: " ret
    fi
    echo "${ret}"
}

calc_heap_entry_code() {
    rtlpLFHKey="0x$1"
    heap="0x$2"
    heapEntryAddress="0x$3"
    heapEntrySize="0x$4"

    echo "obase=16; ibase=10; $((((($heapEntryAddress)/8) ^ $rtlpLFHKey ^ $heap ^ $heapEntrySize) + 4))" | bc
}

heap_entry_code() {
    if [ $# -le 7 ]
    then
        rtlpLFHKey=$(read_input "rtlpLFHKey" "$1")
        heap=$(read_input "heap" "$2")
        heapEntryAddress=$(read_input "heapEntryAddress" "$3")
        heapEntrySize=$(read_input "heapEntrySize/8" "$4")

        calc_heap_entry_code $rtlpLFHKey $heap $heapEntrySize $heapEntryAddress
    else
        # 输入rtlpLFHKey、HEAP、_HEAP_ENTRY地址、_HEAP_ENTRY开始8个byte的内容
        calc_heap_entry_code $1 $2 $3 $7$6$5$4
    fi
}
