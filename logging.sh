if [[ -t 1 ]]; then
    INFO_FORMAT="\\033[00;34m"
    USER_FORMAT="\\033[00;33m"
    SUCCESS_FORMAT="\\033[00;32m"
    WARN_FORMAT="\\033[00;33m"
    SKIP_FORMAT="\\033[00;35m"
    FAIL_FORMAT="\\033[00;31m"
    HIGHLIGHT1_FORMAT="\\033[00;33m"
    HIGHLIGHT2_FORMAT="\\033[00;32m"
    RESET_FORMAT="\\033[0m"
else
    INFO_FORMAT=
    USER_FORMAT=
    SUCCESS_FORMAT=
    WARN_FORMAT=
    SKIP_FORMAT=
    FAIL_FORMAT=
    HIGHLIGHT1_FORMAT=
    HIGHLIGHT2_FORMAT=
    RESET_FORMAT=
fi


debug () {
    fmt="$1"
    shift
    [[ -n "${VERBOSE}" ]] && printf "  [ ${INFO_FORMAT}..${RESET_FORMAT} ] ${fmt}\n" "$@" 1>&2
}

info () {
    fmt="$1"
    shift
    printf "  [ ${INFO_FORMAT}..${RESET_FORMAT} ] ${fmt}\n" "$@" 1>&2
}

user () {
    fmt="$1"
    shift
    printf "  [ ${USER_FORMAT}??${RESET_FORMAT} ] ${fmt}\n" "$@" 1>&2
}

success () {
    fmt="$1"
    shift
    printf "  [ ${SUCCESS_FORMAT}OK${RESET_FORMAT} ] ${fmt}\n" "$@" 1>&2
}

warn () {
    fmt="$1"
    shift
    printf "  [${WARN_FORMAT}WARN${RESET_FORMAT}] ${fmt}\n" "$@" 1>&2
}

skip () {
    fmt="$1"
    shift
    printf "  [${SKIP_FORMAT}SKIP${RESET_FORMAT}] ${fmt}\n" "$@" 1>&2
}

fail () {
    fmt="$1"
    shift
    printf "  [${FAIL_FORMAT}FAIL${RESET_FORMAT}] ${fmt}\n" "$@" 1>&2
    echo ''
    exit 1
}


