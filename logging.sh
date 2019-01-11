debug () {
    # printf "\r  [ \033[00;34m..\033[0m ] $1\n" 1>&2
    echo > /dev/null
}

info () {
    printf "\r  [ \033[00;34m..\033[0m ] $1\n" 1>&2
}

user () {
    printf "\r  [ \033[0;33m??\033[0m ] $1\n" 1>&2
}

success () {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] $1\n" 1>&2
}

warn () {
    printf "\r\033[2K  [\033[00;33mWARN\033[0m] $1\n" 1>&2
}

skip () {
    printf "\r\033[2K  [\033[00;35mSKIP\033[0m] $1\n" 1>&2
    # echo > /dev/null
}

fail () {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] $1\n" 1>&2
    echo ''
    exit
}


