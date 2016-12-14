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

n2dec() {
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
                echo "$[$base#$i]"
            done
        else    # 从命令行读取
            while [ ! -z "$1" ]
            do
                echo "$[$base#$1]"
                shift
            done
        fi
    fi
}

dec2n() {
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
                echo "obase=$base; ibase=10; $i" | bc
            done
        else    # 从命令行读取
            while [ ! -z "$1" ]
            do
                echo "obase=$base; ibase=10; $1" | bc
                shift
            done
        fi
    fi
}

0x() {
    n2dec 16 "$@"
}

0b() {
    n2dec 2 "$@"
}

0o() {
    n2dec 8 "$@"
}

p16() {
    dec2n 16 "$@"
}

p8() {
    dec2n 8 "$@"
}

p2() {
    dec2n 2 "$@" 
}
