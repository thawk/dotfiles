function = {
    python - << EOD
from math import *
from struct import pack
result=($@)
if isinstance(result, int):
    count=int(ceil(len('{:b}'.format(result))/8.0))
    bytes=pack(">Q",result)[8-count:]
    if isinstance(bytes[0], type('c')):
        bytes=map(ord, bytes)
    print('    '.join((
    '{0}'.format(result),
    '0x{0:0>{1}X}'.format(result, count*2),
    '0o{0:0>{1}o}'.format(result, 1),
    '0b{0:0>{1}b}'.format(result, count*8),
    ''.join([chr(c) if c>=0x20 and c<=0x7e else '.' for c in bytes]),
    )))
else:
    print(result)
EOD
}

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

# join , a b c => a,b,c
join_by () {
    local IFS="$1"
    shift
    echo "$*"
}

# acut 2 3 打印第2和第3个字段。可以支持空格、tab等空白字符
acut () {
    awk "{print $(join_by , ${*/#/\$})}" | column -t
}
