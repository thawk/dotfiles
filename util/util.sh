# 进入与当前tmux session名称一致的目录
cdd() {
    if type tmux &> /dev/null
    then
        cd "$HOME/workspace/$(tmux display-message -p '#S')"
    fi
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

