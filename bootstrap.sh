#!/usr/bin/env bash

# bootstrap installs things.

__ScriptVersion="20190803"

# import ~/.localrc to set environments correctly
[[ -a "$HOME/.localrc" ]] && source "$HOME/.localrc" top

if type perl &> /dev/null; then
    DOTFILES_ROOT="$(dirname "$(perl -e 'use Cwd "abs_path";print abs_path(shift)' "$0")")"
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    DOTFILES_ROOT="$(dirname "$(readlink -f "$0")")"
else
    DOTFILES_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
fi

export DOTFILES_ROOT
export DOTFILES_LOCAL="${XDG_CACHE_HOME:-$HOME/.cache}/dotfiles"
export DOTFILES_ENV=${DOTFILES_ENV:-inet}

source "${DOTFILES_ROOT}/logging.sh"

relpath() {
    if type python3 &> /dev/null
    then
        python3 -c "import os.path; print(os.path.relpath('$1','${2:-$PWD}'))"
    elif type python &> /dev/null
    then
        python -c "import os.path; print(os.path.relpath('$1','${2:-$PWD}'))"
    elif type realpath &> /dev/null
    then
        realpath --relative-to="${2:-$PWD}" "$1"
    fi
}

link_file () {
    local src=$1 dst=$2

    local overwrite=
    local backup=
    local skip=
    local action=

    if [ -f "$dst" ] || [ -d "$dst" ] || [ -L "$dst" ]
    then

        if [ "$overwrite_all" == "false" ] && [ "$backup_all" == "false" ] && [ "$skip_all" == "false" ]
        then

            local currentSrc
            currentSrc="$(readlink "$dst")"

            if [ "$currentSrc" == "$src" ]
            then
                skip=true;
            else
                user "File already exists: $dst ($(basename "$src")), what do you want to do?\n\
                    [s]kip, [S]kip all, [o]verwrite, [O]verwrite all, [b]ackup, [B]ackup all?"
                read -r -n 1 action

                case "$action" in
                    o )
                        overwrite=true;;
                    O )
                        overwrite_all=true;;
                    b )
                        backup=true;;
                    B )
                        backup_all=true;;
                    s )
                        skip=true;;
                    S )
                        skip_all=true;;
                    * )
                        ;;
                esac
            fi
        fi

        overwrite=${overwrite:-$overwrite_all}
        backup=${backup:-$backup_all}
        skip=${skip:-$skip_all}

        if [ "$overwrite" == "true" ]
        then
            if [ "${DRY_RUN}" = 'yes' ]
            then
                echo "      => rm -rf \"$dst\""
            else
                rm -rf "$dst"
            fi
            success "    removed $dst"
        fi

        if [ "$backup" == "true" ]
        then
            if [ "${DRY_RUN}" = 'yes' ]
            then
                echo "      => mv \"$dst\" \"${dst}.backup\""
            else
                mv "$dst" "${dst}.backup"
            fi
            success "moved $dst to ${dst}.backup"
        fi

        if [ "$skip" == "true" ]
        then
            debug "      ${WARN_FORMAT}skipped${RESET_FORMAT} ${INFO_FORMAT}$src${RESET_FORMAT}"
        fi
    fi

    if [ "$skip" != "true" ]  # "false" or empty
    then
        parent=$(dirname "$2")

        if [ ! -d "$parent" ]
        then
            if [ "${DRY_RUN}" = 'yes' ]
            then
                echo "      => mkdir -p \"$parent\""
            else
                mkdir -p "$parent"
            fi
        fi

        if [ "${DRY_RUN}" = 'yes' ]
        then
            echo "      => ln -s \"$1\" \"$2\""
        else
            ln -s "$1" "$2"
        fi
        success "    linked $1 to $2"
    fi

    unset src dst overwrite backup skip action
}

get_symlinks() {
    LINK_BASE="$1"
    shift 1

    for dir in "$@"
    do
        find -H "${LINK_BASE}/$dir" -name '*.symlink' -o -name "*.symlink-${DOTFILES_ENV}" -not -path '*.git' |
            while read -r src
            do
                rel=$(relpath "$src" "$LINK_BASE")
                echo "$rel"
            done
    done

    unset dir src
}

create_symlinks () {
    local dir

    LINK_BASE="$1"
    LINK_FILE="$2"
    shift 2

    info "    ${LINK_BASE} => ${LINK_FILE} ..."

    local -A links
    
    for link in $(get_symlinks "$LINK_BASE" "$@")
    do
        links["$link"]="$link"
    done

    if [ -e "$DOTFILES_LOCAL/$LINK_FILE" ]
    then
        while read -r link
        do
            if [ -z "${links[$link]+isset}" ]
            then
                dst="$TARGET/${link#*/}"
                dst="${dst%.symlink*}"

                if [ -h "$dst" ]
                then
                    if [ "$LINK_BASE/$link" == "$(readlink "$dst")" ]
                    then
                        if [ "${DRY_RUN}" = 'yes' ]
                        then
                            echo "      => rm \"$dst\""
                        else
                            rm "$dst"
                        fi
                        success "    remove outdated \"$dst\""
                    else
                        skip "    $dst is not point to original position, don't need to be remove"
                    fi
                else
                    skip "    $dst is not exists, or not a symbol link, don't need to be remove"
                fi
            fi
        done < "$DOTFILES_LOCAL/$LINK_FILE"
    fi

    mkdir -p "$DOTFILES_LOCAL"
    cat /dev/null > "$DOTFILES_LOCAL/$LINK_FILE"
    for link in "${links[@]}"
    do
        echo "$link" >> "$DOTFILES_LOCAL/$LINK_FILE"
        dst="$TARGET/${link#*/}"
        dst="${dst%.symlink*}"
        link_file "$LINK_BASE/$link" "$dst"
    done
}

generate_source_list () {
    local f dir shell orig_nullglob
    local path_env fpath_env
    local -a path_sh env_sh completion_sh others_sh top_sh_sh

    shell="$1"

    info "    Generating script files for ${HIGHLIGHT1_FORMAT}${shell}${RESET_FORMAT}..."

    stage0_file="$DOTFILES_LOCAL/stage0.${shell}"
    stage1_file="$DOTFILES_LOCAL/stage1.${shell}"
    stage2_file="$DOTFILES_LOCAL/stage2.${shell}"

    orig_nullglob=
    shopt nullglob > /dev/null && orig_nullglob=1
    shopt -s nullglob

    # shellcheck disable=SC2016
    path_env='export PATH=$PATH'
    # shellcheck disable=SC2016
    fpath_env='export fpath=($fpath'

    while [ $# -gt 1 ]
    do
        shift

        dir=$1
        debug "      Handling subdir ${SUCCESS_FORMAT}${dir}${RESET_FORMAT}..."

        if [ -d "${DOTFILES_ROOT}/${dir}/bin" ]; then
            path_env="${path_env}:${DOTFILES_ROOT}/${dir}/bin"
            debug "        Add ${INFO_FORMAT}${dir}/bin${RESET_FORMAT} to ${INFO_FORMAT}\$PATH${RESET_FORMAT}..."
        fi

        if [ -d "${DOTFILES_ROOT}/${dir}/zsh-completion" ]; then
            fpath_env="${fpath_env} ${DOTFILES_ROOT}/${dir}/zsh-completion"
            debug "        Add ${INFO_FORMAT}${dir}/zsh-completion${RESET_FORMAT} to ${INFO_FORMAT}\$fpath${RESET_FORMAT}..."
        fi

        for f in "${DOTFILES_ROOT}/${dir}"/*.{sh,"${shell}"} "${DOTFILES_LOCAL}/${dir}"/*.{sh,"${shell}"}
        do
            if [ ! -f "$f" ]; then
                continue
            fi

            if [[ "${f##*/}" =~ ^path\.[^.]*$ ]]; then
                path_sh[${#path_sh[*]}]="$f"
                debug "        Add ${INFO_FORMAT}$f${RESET_FORMAT} to ${INFO_FORMAT}path.sh${RESET_FORMAT}..."
            elif [[ "${f##*/}" =~ ^env\.[^.]*$ ]]; then
                env_sh[${#env_sh[*]}]="$f"
                debug "        Add ${INFO_FORMAT}$f${RESET_FORMAT} to ${INFO_FORMAT}env.sh${RESET_FORMAT}..."
            elif [[ "${f##*/}" =~ ^completion\.[^.]*$ ]]; then
                completion_sh[${#completion_sh[*]}]="$f"
                debug "        Add ${INFO_FORMAT}$f${RESET_FORMAT} to ${INFO_FORMAT}completion.sh${RESET_FORMAT}..."
            elif [[ "${f##*/}" =~ ^top_sh\.[^.]*$ ]]; then
                top_sh_sh[${#top_sh_sh[*]}]="$f"
                debug "        Add ${INFO_FORMAT}$f${RESET_FORMAT} to ${INFO_FORMAT}top_sh.sh${RESET_FORMAT}..."
            elif [[ "${f##*/}" =~ ^requirements\.[^.]*$ ]]; then
                # debug "        Ignoring $f..."
                true
            elif [[ "${f##*/}" =~ ^bootstrap\.[^.]*$ ]]; then
                # debug "        Ignoring $f..."
                true
            else
                others_sh[${#others_sh[*]}]="$f"
                debug "        Add ${INFO_FORMAT}$f${RESET_FORMAT} to ${INFO_FORMAT}others.sh${RESET_FORMAT}..."
            fi
        done
    done

    fpath_env="${fpath_env})"

    # reset nullglob if original value is false
    [ -z "$orig_nullglob" ] && shopt -u nullglob

    # stage0 - for top shell, SHLVL=1
    info "      ${stage0_file%/*}/${HIGHLIGHT2_FORMAT}${stage0_file##*/}${RESET_FORMAT}"
    cat /dev/null > "${stage0_file}"

    echo "### top_sh scripts ###" >> "${stage0_file}"
    echo "" >> "${stage0_file}"

    for f in "${top_sh_sh[@]}"
    do
        debug "        ${f%/*}/${HIGHLIGHT2_FORMAT}${f##*/}${RESET_FORMAT}"

        (
            echo "# Script $f"
            cat "$f"
            echo ""
        ) >> "${stage0_file}"
    done

    echo "${path_env}" >> "${stage0_file}"

    # stage1
    info "      ${stage1_file%/*}/${HIGHLIGHT2_FORMAT}${stage1_file##*/}${RESET_FORMAT}"

    cat /dev/null > "${stage1_file}"

    if [ "$shell" == "zsh" ]; then
        echo "${fpath_env}" >> "${stage1_file}"
    fi

    echo "" >> "${stage1_file}"

    echo "### set paths ###" >> "${stage1_file}"
    for f in "${path_sh[@]}"
    do
        debug "        ${f%/*}/${HIGHLIGHT2_FORMAT}${f##*/}${RESET_FORMAT}"

        (
            echo "# Script $f"
            cat "$f"
            echo ""
        ) >> "${stage1_file}"
    done

    echo "" >> "${stage1_file}"
    echo "### set environments ###" >> "${stage1_file}"
    for f in "${env_sh[@]}"
    do
        debug "        ${f%/*}/${HIGHLIGHT2_FORMAT}${f##*/}${RESET_FORMAT}"

        (
            echo "# Script $f"
            cat "$f"
            echo ""
        ) >> "${stage1_file}"
    done

    echo "" >> "${stage1_file}"

    # stage2
    info "      ${stage2_file%/*}/${HIGHLIGHT2_FORMAT}${stage2_file##*/}${RESET_FORMAT}"
    cat /dev/null > "${stage2_file}"

    echo "### others scripts ###" >> "${stage2_file}"
    echo "" >> "${stage2_file}"

    for f in "${others_sh[@]}"
    do
        debug "        ${f%/*}/${HIGHLIGHT2_FORMAT}${f##*/}${RESET_FORMAT}"

        (
            echo "# Script $f"
            cat "$f"
            echo ""
        ) >> "${stage2_file}"
    done

    echo "" >> "${stage2_file}"
    echo "### completion scripts ###" >> "${stage2_file}"
    for f in "${completion_sh[@]}"
    do
        debug "        ${f%/*}/${HIGHLIGHT2_FORMAT}${f##*/}${RESET_FORMAT}"

        (
            echo "# Script $f"
            cat "$f"
            echo ""
        ) >> "${stage2_file}"
    done
}

function join_by {
    local d=$1
    shift
    echo -n "$1"
    shift
    printf "%s" "${@/#/$d}"
}

get_enabled_plugins() {
    local dir
    local old_path=$PATH
    local -a dirs

    IFS=$'\n' read -r -d '' -a dirs < <(find "$DOTFILES_ROOT" -maxdepth 1 -type d ! -name '.*' | sort)

    info "Checking plugins status..."

    mkdir -p "$DOTFILES_LOCAL"
    : > "$DOTFILES_LOCAL/enabled.new.txt"

    for dir in "${dirs[@]}"
    do
        [ -d "$dir/bin" ] && PATH=$PATH:"$dir/bin"
    done

    for dir in "${dirs[@]}"
    do
        if [ -e "${dir}/disabled" ] || [ -e "${dir}/disabled.global" ]
        then
            debug "    ${WARN_FORMAT}Disable${RESET_FORMAT} ${INFO_FORMAT}${dir}${RESET_FORMAT} for global"
            echo "# $(basename "${dir}")" >> "$DOTFILES_LOCAL/enabled.new.txt"
            continue
        fi

        if [ -f "${dir}/requirements.sh" ] && ! "${dir}/requirements.sh" &> /dev/null
        then
            debug "    ${WARN_FORMAT}Disable${RESET_FORMAT} ${INFO_FORMAT}${dir}${RESET_FORMAT} for requirements.sh"
            echo "# $(basename "${dir}")" >> "$DOTFILES_LOCAL/enabled.new.txt"
            continue
        fi

        basename "${dir}" >> "$DOTFILES_LOCAL/enabled.new.txt"
        basename "${dir}"
    done

    PATH=$old_path
}

generate_files() {
    local -A old_enabled
    local dir

    if [ -e "$DOTFILES_LOCAL/enabled.txt" ]
    then
        while read -r dir
        do
            old_enabled["$dir"]="0"
        done < <( grep "^[^#]" "$DOTFILES_LOCAL/enabled.txt" )
    fi

    for dir in "$@"
    do
        if [ -z "${old_enabled[$dir]+isset}" ]
        then
            info "    ${SUCCESS_FORMAT}Enable${RESET_FORMAT} ${INFO_FORMAT}${dir}${RESET_FORMAT}"
        else
            old_enabled["$dir"]="1"
            debug "    ${SUCCESS_FORMAT}Enable${RESET_FORMAT} ${INFO_FORMAT}${dir}${RESET_FORMAT}"
        fi

        # run bootstrap file
        bootstrap_file=
        if [ -f "${DOTFILES_ROOT}/${dir}/bootstrap.sh" ]
        then
            bootstrap_file="${DOTFILES_ROOT}/${dir}/bootstrap.sh"
        elif [ -f "${DOTFILES_ROOT}/${dir}/bootstrap" ]
        then
            bootstrap_file="${DOTFILES_ROOT}/${dir}/bootstrap"
        fi

        if [ -n "${bootstrap_file}" ]
        then
            if [ -x "${bootstrap_file}" ]
            then
                debug "      Executing ${bootstrap_file}"
                "${bootstrap_file}" "${DRY_RUN}"
            else
                fail "'${bootstrap_file}' must be executable!"
            fi
        fi
    done

    for dir in "${!old_enabled[@]}"
    do
        if [ "${old_enabled[$dir]}" == "0" ]
        then
            info "    ${WARN_FORMAT}Disable${RESET_FORMAT} ${INFO_FORMAT}${dir}${RESET_FORMAT}"
        fi
    done

    info "    ${SUCCESS_FORMAT}Done${RESET_FORMAT}"

    generate_script_file "$@"

    local overwrite_all=false backup_all=false skip_all=false

    info ""
    info "Creating symbol links..."

    create_symlinks "${DOTFILES_ROOT}" "links.txt" "$@"
    create_symlinks "${DOTFILES_LOCAL}" "links_local.txt" .

    info "    ${SUCCESS_FORMAT}Done${RESET_FORMAT}"
}

generate_script_file() {
    local dir=
    local shell=

    info ""
    info "Generating script files for shells..."

    for shell in bash zsh
    do
        generate_source_list $shell "$@"
    done
}

list_plugins() {
    if [ -e "$DOTFILES_LOCAL/enabled.txt" ]
    then
        cat "$DOTFILES_LOCAL/enabled.txt"
    fi
}

update_subtrees() {
    cat "${DOTFILES_ROOT}/subtrees.txt" |
        grep -v '^#' |
        while read prefix url branch; do
            git subtree pull --squash --prefix "${prefix}" "${url}" "${branch}"
        done
}

echo_usage()
{
    echo "
Usage: $(basename "$0") [options] [--]

    Options:
        -h|help                 Display this message
        -l|list                 List plugins
        -u|update               Update subtrees
        -V|version              Display script version
        -v|verbose              Display more verbose log
        -t|target <TARGET_DIR>  Target directory, defaults to \$HOME
        -d|dry-run              Print modification instead of apply it
" >&2
}

DRY_RUN=
VERBOSE=
TARGET="$HOME"

while getopts ":hluVvt:d" opt; do
    case $opt in
        h) # |help)
            echo_usage
            exit 0
            ;;
        l) # |list)
            list_plugins
            exit 0
            ;;
        u) # |update)
            update_subtrees
            exit 0
            ;;
        V) # |version)
            echo "$(basename "$0") -- Version $__ScriptVersion"
            exit 0
            ;;
        v) # |verbose)
            VERBOSE="${VERBOSE}1"
            ;;
        t) # |target)
            TARGET="$OPTARG"
            ;;
        d) # |dry-run)
            DRY_RUN=yes
            ;;
        * )
            echo -e "\n  Option does not exist : '$OPTARG' at position $OPTIND\n"
            echo_usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

if [ "${DRY_RUN}" = 'yes' ]
then
    info "!!! ${WARN_FORMAT}DRY RUN${RESET_FORMAT} !!!"
    info ""
else
    info "!!! ${SUCCESS_FORMAT}Apply mode${RESET_FORMAT} !!!"
    info ""
fi

info "Environments:"
info "    ${HIGHLIGHT1_FORMAT}DOTFILES_ROOT${RESET_FORMAT}  = ${HIGHLIGHT2_FORMAT}${DOTFILES_ROOT}${RESET_FORMAT}"
info "    ${HIGHLIGHT1_FORMAT}DOTFILES_LOCAL${RESET_FORMAT} = ${HIGHLIGHT2_FORMAT}${DOTFILES_LOCAL}${RESET_FORMAT}"
info "    ${HIGHLIGHT1_FORMAT}DOTFILES_ENV${RESET_FORMAT}   = ${HIGHLIGHT2_FORMAT}${DOTFILES_ENV}${RESET_FORMAT}"
info ""

info "Install to $TARGET..."
info ""

typeset -a dirs

IFS=$'\n' read -r -d '' -a dirs < <(get_enabled_plugins)

generate_files "${dirs[@]}"
[ -e "$DOTFILES_LOCAL/enabled.new.txt" ] && mv "$DOTFILES_LOCAL/enabled.new.txt" "$DOTFILES_LOCAL/enabled.txt"


# Delete zsh completion dump file, force regeneration
[ -e ~/.zcompdump ] && rm ~/.zcompdump

unset dirs

info ""
info "${SUCCESS_FORMAT}Done!${RESET_FORMAT}"
