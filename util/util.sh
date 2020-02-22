cdd() {
    if type tmux &> /dev/null
    then
        # 如果当前tmux session名称正好是$DOTFILES_SRC_ROOT下的目录名，则进入该目录
        local proj_name="$(tmux display-message -p '#S')"
        local src_root="${DOTFILES_SRC_ROOT:-$HOME/workspace}"

        if [[ -d "${src_root}/${proj_name}" ]]; then
            cd "${src_root}/${proj_name}"
            return
        fi
    fi

    # 没有找到与tmux session名称对应的项目，找当前目录往上的VCS目录作为项目的根目录
    # 如果有多个VCS目录，说明存在一些子项目，取最顶层目录
    local last_proj_root=
    local dir="$PWD"
    local last_dir=

    while [[ "$dir" != "$last_dir" ]]; do
        for d in .git _darcs .hg .bzr .svn; do
            if [[ -e "$dir/$d" ]]; then
                last_proj_root="$dir"
                break
            fi
        done

        last_dir="$dir"
        dir="$(dirname "$dir")"
    done

    if [[ -d "$last_proj_root" ]]; then
        cd "$last_proj_root"
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

