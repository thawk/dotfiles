# 进入与当前tmux session名称一致的目录
cdd() {
    if type tmux &> /dev/null
    then
        cd "$HOME/workspace/$(tmux display-message -p '#S')"
    fi
}

timestamp() {
    while [ $# -gt 0 ]
    do
        timestamp=$1
        date -d @$((timestamp / 1000000)) +"%Y-%m-%d %T".$((timestamp % 1000000))
        shift
    done
}

epochtime() {
    while [ $# -gt 0 ]
    do
        epochtime=$1
        date -d @$((epochtime / 1000)) +"%Y-%m-%d %T".$((epochtime % 1000))
        shift
    done
}

time_t() {
    while [ $# -gt 0 ]
    do
        time_t=$1
        date -d @$((time_t)) +"%Y-%m-%d %T"
        shift
    done
}

grepp() {
  if test -z "$1"; then
    echo "USAGE: grepp searchterm [filetosearch]";
  elif test -z "$2"; then
    perl -00ne "print if /$1/i"
  else
    term=$1
    shift
    while ! test -z "$1"
    do
        perl -00ne "print if /$term/i" < $1
        shift
    done
  fi 
}

urlencode() {
    if [ $# -gt 0 ];
    then
        echo "$@" | perl -MURI::Escape -lne 'print uri_escape($_)'
    else
        perl -MURI::Escape -lne 'print uri_escape($_)'
    fi
}

urldecode() {
    if [ $# -gt 0 ];
    then
        echo "$@" | perl -MURI::Escape -lne 'print uri_unescape($_)'
    else
        perl -MURI::Escape -lne 'print uri_unescape($_)'
    fi
}

htmlencode() {
    if [ $# -gt 0 ]
    then
        echo "$@" | perl -lne "use HTML::Entities qw(encode_entities_numeric); use open(':locale'); print encode_entities_numeric(\$_,'<&>\\x0-\\x1f')"
    else
        perl -lne "use HTML::Entities qw(encode_entities_numeric); use open(':locale'); print encode_entities_numeric(\$_,'<&>\\x0-\\x1f')"
    fi
}

htmldecode() {
    if [ $# -gt 0 ];
    then
        echo "$@" | perl -MHTML::Entities -lne 'print decode_entities($_)'
    else
        perl -MHTML::Entities -lne 'print decode_entities($_)'
    fi
}

ansiesc() {
    sed -e 's/\[[0-9;]\+m//g'
}

vman () {
    vim +"set ft=man" +"Man $*"
}

dec2hex() {
    if [ $# -eq 0 ]
    then    # 从stdin读取
        while read i
        do
            dec2hex $i
        done
    else    # 从命令行读取
        while [ ! -z "$1" ]
        do
            echo "obase=16; ibase=10; $1" | bc
            shift
        done
    fi
}

hex2dec() {
    if [ $# -eq 0 ]
    then    # 从stdin读取
        while read i
        do
            hex2dec $i
        done
    else    # 从命令行读取
        while [ ! -z "$1" ]
        do
            echo $((0x$1))
            shift
        done
    fi
}

b362dec() {
    while [ ! -z "$1" ]
    do
        echo $((36#$1))
        shift
    done
}

dec2b36() {
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
