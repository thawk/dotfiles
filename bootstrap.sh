#!/usr/bin/env bash
#
# bootstrap installs things.

if type perl &> /dev/null; then
    DOTFILES_ROOT="$(dirname $(perl -e 'use Cwd "abs_path";print abs_path(shift)' $0))"
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    DOTFILES_ROOT="$(dirname "$(readlink -f "$0")")"
else
    DOTFILES_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
fi

export DOTFILES_ROOT
export DOTFILES_LOCAL="${XDG_CACHE_HOME:-$HOME/.cache}/dotfiles"

set -e

source "${DOTFILES_ROOT}/logging.sh"

relpath() {
    if type python &> /dev/null
    then
        python -c "import os.path; print(os.path.relpath('$1','${2:-$PWD}'))"
    elif type realpath &> /dev/null
    then
        realpath --relative-to="${2:-$PWD}" "$1"
    fi
}

link_file () {
    local src=$1 dst=$2

    local overwrite= backup= skip=
    local action=

    if [ -f "$dst" -o -d "$dst" -o -L "$dst" ]
    then

        if [ "$overwrite_all" == "false" ] && [ "$backup_all" == "false" ] && [ "$skip_all" == "false" ]
        then

            local currentSrc="$(readlink $dst)"

            if [ "$currentSrc" == "$src" ]
            then
                skip=true;
            else
                user "File already exists: $dst ($(basename "$src")), what do you want to do?\n\
                    [s]kip, [S]kip all, [o]verwrite, [O]verwrite all, [b]ackup, [B]ackup all?"
                read -n 1 action

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
            debug "      skipped $src"
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
        for src in $(find -H "${LINK_BASE}/$dir" -name '*.symlink' -not -path '*.git')
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
        for link in $( cat "$DOTFILES_LOCAL/$LINK_FILE" )
        do
            if [ -z "${links[$link]+isset}" ]
            then
                dst="$TARGET/${link#*/}"
                dst="${dst%.symlink}"

                if [ -h "$dst" ]
                then
                    if [ "$LINK_BASE/$link" == "$(readlink $dst)" ]
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
        done
    fi

    mkdir -p "$DOTFILES_LOCAL"
    cat /dev/null > "$DOTFILES_LOCAL/$LINK_FILE"
    for link in "${links[@]}"
    do
        echo "$link" >> "$DOTFILES_LOCAL/$LINK_FILE"
        dst="$TARGET/${link#*/}"
        dst="${dst%.symlink}"
        link_file "$LINK_BASE/$link" "$dst"
    done
}

generate_source_list () {
    local f dir shell orig_nullglob
    local path_env fpath_env
    local -a path_sh env_sh completion_sh others_sh

    shell="$1"

    info "    Generating script files for ${shell}..."

    stage1_file="$DOTFILES_LOCAL/stage1.${shell}"
    stage2_file="$DOTFILES_LOCAL/stage2.${shell}"

    orig_nullglob=
    shopt nullglob > /dev/null && orig_nullglob=1
    shopt -s nullglob

    path_env='export PATH=$PATH'
    fpath_env='export fpath=($fpath'

    while [ $# -gt 1 ]
    do
        shift

        dir=$1
        debug "    Handling subdir ${dir}..."

        if [ -d "${DOTFILES_ROOT}/${dir}/bin" ]; then
            path_env="${path_env}:${DOTFILES_ROOT}/${dir}/bin"
            debug "      Add ${dir}/bin to \$PATH..."
        fi

        if [ -d "${DOTFILES_ROOT}/${dir}/zsh-completion" ]; then
            fpath_env="${fpath_env} ${DOTFILES_ROOT}/${dir}/zsh-completion"
            debug "      Add ${dir}/zsh-completion to \$fpath..."
        fi

        for f in "${DOTFILES_ROOT}/${dir}"/*.{sh,"${shell}"} "${DOTFILES_LOCAL}/${dir}"/*.{sh,"${shell}"}
        do
            if [ ! -f "$f" ]; then
                continue
            fi

            if [[ "${f##*/}" =~ ^path\.[^.]*$ ]]; then
                path_sh[${#path_sh[*]}]="$f"
                debug "      Add $f to path.sh..."
            elif [[ "${f##*/}" =~ ^env\.[^.]*$ ]]; then
                env_sh[${#env_sh[*]}]="$f"
                debug "      Add $f to env.sh..."
            elif [[ "${f##*/}" =~ ^completion\.[^.]*$ ]]; then
                completion_sh[${#completion_sh[*]}]="$f"
                debug "      Add $f to completion.sh..."
            elif [[ "${f##*/}" =~ ^requirements\.[^.]*$ ]]; then
                debug "      Ignoring $f..."
            elif [[ "${f##*/}" =~ ^bootstrap\.[^.]*$ ]]; then
                debug "      Ignoring $f..."
            else
                others_sh[${#others_sh[*]}]="$f"
                debug "      Add $f to others.sh..."
            fi
        done
    done

    fpath_env="${fpath_env})"

    # reset nullglob if original value is false
    [ -z "$orig_nullglob" ] && shopt -u nullglob

    info "        ${stage1_file}"

    cat /dev/null > "${stage1_file}"

    echo "${path_env}" >> "${stage1_file}"

    if [ "$shell" == "zsh" ]; then
        echo "${fpath_env}" >> "${stage1_file}"
    fi

    echo "" >> "${stage1_file}"

    echo "### set paths ###" >> "${stage1_file}"
    for f in "${path_sh[@]}"
    do
        echo "# Script $f" >> "${stage1_file}"
        cat "$f" >> "${stage1_file}"
        echo "" >> "${stage1_file}"
    done

    echo "" >> "${stage1_file}"
    echo "### set environments ###" >> "${stage1_file}"
    for f in "${env_sh[@]}"
    do
        echo "# Script $f" >> "${stage1_file}"
        cat "$f" >> "${stage1_file}"
        echo "" >> "${stage1_file}"
    done

    echo "" >> "${stage1_file}"

    # stage2
    info "        ${stage2_file}"
    cat /dev/null > "${stage2_file}"

    echo "### others scripts ###" >> "${stage2_file}"
    echo "" >> "${stage2_file}"

    for f in "${others_sh[@]}"
    do
        echo "# Script $f" >> "${stage2_file}"
        cat "$f" >> "${stage2_file}"
        echo "" >> "${stage2_file}"
    done

    echo "" >> "${stage2_file}"
    echo "### completion scripts ###" >> "${stage2_file}"
    for f in "${completion_sh[@]}"
    do
        echo "# Script $f" >> "${stage2_file}"
        cat "$f" >> "${stage2_file}"
        echo "" >> "${stage2_file}"
    done
}

function join_by {
    local d=$1
    shift
    echo -n "$1"
    shift
    printf "%s" "${@/#/$d}"
}

get_enabled_dir() {
    local dir
    local old_path=$PATH
    local -a dirs=( $(find "$DOTFILES_ROOT" -maxdepth 1 -type d ! -name '.*' | sort) ) 

    info "Checking plugins status..."

    for dir in "${dirs[@]}"
    do
        [ -d "$dir/bin" ] && PATH=$PATH:"$dir/bin"
    done

    for dir in "${dirs[@]}"
    do
        if [ -e "${dir}/disabled" ]
        then
            continue
        fi

        if [ -f "${dir}/requirements.sh" ] && ! "${dir}/requirements.sh" &> /dev/null
        then
            continue
        fi

        echo $(basename ${dir})
    done

    PATH=$old_path

    info '    Done'
}

generate_files() {
    local -A old_enabled
    local dir

    if [ -e "$DOTFILES_LOCAL/enabled.txt" ]
    then
        for dir in $( cat "$DOTFILES_LOCAL/enabled.txt" )
        do
            old_enabled["$dir"]="0"
        done
    fi

    mkdir -p "$DOTFILES_LOCAL"
    cat /dev/null > "$DOTFILES_LOCAL/enabled.txt"

    for dir in "$@"
    do
        if [ -z "${old_enabled[$dir]+isset}" ]
        then
            info "    Enable ${dir}"
        else
            old_enabled["$dir"]="1"
            debug "    Enable ${dir}"
        fi

        echo "${dir}" >> "$DOTFILES_LOCAL/enabled.txt"

        # run bootstrap file
        bootstrap_file=
        if [ -f "${dir}/bootstrap.sh" ]
        then
            bootstrap_file="${dir}/bootstrap.sh"
        elif [ -f "${dir}/bootstrap" ]
        then
            bootstrap_file="${dir}/bootstrap"
        fi

        if [ -n "${bootstrap_file}" ]
        then
            if [ -x "${bootstrap_file}" ]
            then
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
            info "    Disable ${dir}"
        fi
    done

    generate_script_file "$@"

    local overwrite_all=false backup_all=false skip_all=false

    info "Creating symbol links..."

    create_symlinks "${DOTFILES_ROOT}" "links.txt" "$@"
    create_symlinks "${DOTFILES_LOCAL}" "links_local.txt" .

    info '    Done'
}

generate_script_file() {
    local dir= shell= script_name=

    info "Generating script files for shells..."

    for shell in bash zsh
    do
        generate_source_list $shell "$@"
    done
}

function EchoUsage()
{
    echo "
Usage: $(basename "$0") [options]

  Options:
      -h [ --help ]                show this screen
      --dry-run                    print modify instead of apply it
      -t [ --target=<TARGET_DIR> ] target directory, defaults to \$HOME
      -v [ --verbose ]             show debug log
" >&2
}

TEMP=$(getopt -o h,t: --long help,dry-run,target: -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

# Note the quotes around `$TEMP': they are essential!
eval set -- "$TEMP"

DRY_RUN=no
TARGET=$HOME

while true ; do
    case "$1" in
        -h|--help)
            EchoUsage
            exit 1
            ;;
        --dry-run)
            DRY_RUN=yes
            shift 1
            ;;
        -t|--target)
            TARGET=$2
            shift 2
            ;;
        --)
            shift 1
            break
            ;;
        *)
            echo "Unknown parameter '$1'!"
            exit 1
            ;;
    esac
done

if [ "${DRY_RUN}" = 'yes' ]
then
    info "!!! DRY RUN !!!"
    info ""
else
    info "!!! Apply mode !!!"
    info ""
fi

info "Environments:"
info "    DOTFILES_ROOT=${DOTFILES_ROOT}"
info "    DOTFILES_LOCAL=${DOTFILES_LOCAL}"

if [ -d "${DOTFILES_ROOT}/.git" ]
then
    info 'Setup submodules...'
    pushd "${DOTFILES_ROOT}" > /dev/null
    git submodule init
    git submodule update
    popd > /dev/null
    info '    Done'
fi

typeset -a dirs

dirs=( $(get_enabled_dir) )
generate_files "${dirs[@]}"

# Delete zsh completion dump file, force regeneration
[ -e ~/.zcompdump ] && rm ~/.zcompdump

unset dirs

info 'Done!'
