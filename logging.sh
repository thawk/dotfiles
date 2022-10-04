debug () {
    [[ -n "${VERBOSE}" ]] && printf "\r  [ \033[00;34m..\033[0m ] %s\n" "$*" 1>&2
    true
}

info () {
    fmt="$1"
    shift
    printf "\r  [ \033[00;34m..\033[0m ] ${fmt}\n" "$@" 1>&2
}

user () {
    printf "\r  [ \033[0;33m??\033[0m ] ${fmt}\n" "$@" 1>&2
}

success () {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] ${fmt}\n" "$@" 1>&2
}

warn () {
    printf "\r\033[2K  [\033[00;33mWARN\033[0m] ${fmt}\n" "$@" 1>&2
}

skip () {
    printf "\r\033[2K  [\033[00;35mSKIP\033[0m] ${fmt}\n" "$@" 1>&2
    true
}

fail () {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] ${fmt}\n" "$@" 1>&2
    echo ''
    exit 1
}


