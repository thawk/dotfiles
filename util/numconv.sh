0b36() {
    while [ ! -z "$1" ]
    do
        echo $((36#$1))
        shift
    done
}

p36() {
    b36arr=($(echo {0..9} {A..Z}))
    while [ ! -z "$1" ]
    do
        for i in $(echo "obase=36; $1" | bc)
        do
            echo -n ${b36arr[${i#0}]}
        done
        echo
        shift
    done
}

_num_conv() {
    if [ $# -eq 0 ]
    then    # 至少需要一个参数以指定进制
        echo "Need at least one parameter" > /dev/stderr
        return
    else
        base=$1
        shift
        if [ $# -eq 0 ]
        then    # 从stdin读取
            while read i
            do
                = "${base}${i}"
            done
        else    # 从命令行读取
            while [ ! -z "$1" ]
            do
                = "${base}${1}"
                shift
            done
        fi
    fi | column -t
}

num() {
    _num_conv "" "$@"
}

0d() {
    _num_conv "" "$@"
}

0x() {
    _num_conv 0x "$@"
}

0b() {
    _num_conv 0b "$@"
}

0o() {
    _num_conv 0o "$@"
}


