#!/usr/bin/env bash
#
# bootstrap installs things.

DOTFILES_ROOT="$(dirname "$(readlink -f "$0")")"
DOTFILES_LOCAL="${HOME}/.dotfiles.local"

set -e

debug () {
    # printf "\r  [ \033[00;34m..\033[0m ] $1\n" > /dev/stderr
    echo > /dev/null
}

info () {
    printf "\r  [ \033[00;34m..\033[0m ] $1\n" > /dev/stderr
}

user () {
    printf "\r  [ \033[0;33m??\033[0m ] $1\n" > /dev/stderr
}

success () {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] $1\n" > /dev/stderr
}

warn () {
    printf "\r\033[2K  [\033[00;33mWARN\033[0m] $1\n" > /dev/stderr
}

skip () {
    printf "\r\033[2K  [\033[00;35mSKIP\033[0m] $1\n" > /dev/stderr
    # echo > /dev/null
}

fail () {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] $1\n" > /dev/stderr
    echo ''
    exit
}

relpath() {
    if type python &> /dev/null
    then
        python -c "import os.path; print(os.path.relpath('$1','${2:-$PWD}'))"
    elif type realpath &> /dev/null
    then
        realpath --relative-to="${2:-$PWD}" "$1"
    fi
}

setup_gitconfig () {
    if ! [ -f $DOTFILES_LOCAL/.gitconfig.local.symlink ]
    then
        info 'setup gitconfig'

        git_credential='cache'
        if [ "$(uname -s)" == "Darwin" ]
        then
            git_credential='osxkeychain'
        fi

        user ' - What is your github author name?'
        read -e git_authorname
        user ' - What is your github author email?'
        read -e git_authoremail

        if [ "${DRY_RUN}" = 'yes' ]
        then
            echo .gitconfig.local.symlink
            sed -e "s/AUTHORNAME/$git_authorname/g" -e "s/AUTHOREMAIL/$git_authoremail/g" -e "s/GIT_CREDENTIAL_HELPER/$git_credential/g" $DOTFILES_ROOT/git/.gitconfig.local.symlink.example
        else
            mkdir -p "$DOTFILES_LOCAL"
            sed -e "s/AUTHORNAME/$git_authorname/g" -e "s/AUTHOREMAIL/$git_authoremail/g" -e "s/GIT_CREDENTIAL_HELPER/$git_credential/g" $DOTFILES_ROOT/git/.gitconfig.local.symlink.example > $DOTFILES_LOCAL/.gitconfig.local.symlink
        fi

        success 'gitconfig'
    fi
}


setup_taskrc () {
    if ! [ -f $DOTFILES_LOCAL/.taskrc.symlink ]
    then
        info 'setup taskrc'

        if [ "${DRY_RUN}" = 'yes' ]
        then
            echo .taskrc.symlink
        else
            mkdir -p "$DOTFILES_LOCAL"
            cp $DOTFILES_ROOT/taskwarrior/.taskrc.symlink.example $DOTFILES_LOCAL/.taskrc.symlink
        fi

        success 'taskrc'
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
            success "  removed $dst"
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
            debug "  skipped $src"
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
        success "  linked $1 to $2"
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

    info "Creating symbol links for ${LINK_BASE} into ${LINK_FILE}..."

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
                        success "  remove outdated \"$dst\""
                    else
                        skip "  $dst is not point to original position, don't need to be remove"
                    fi
                else
                    skip "  $dst is not exists, or not a symbol link, don't need to be remove"
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

get_zsh_completions() {
    local dir=

    for dir in "$@"
    do
        [ -d "${dir}/zsh-completion" ] && echo "${dir}/zsh-completion"
    done
}

generate_source_list () {
    local f dir shell orig_nullglob
    local -a path_sh env_sh completion_sh others_sh

    shell="$1"

    orig_nullglob=
    shopt nullglob > /dev/null && orig_nullglob=1
    shopt -s nullglob

    while [ $# -gt 1 ]
    do
        shift

        dir=$1
        debug "    Handling subdir ${dir}..."

        for f in "${DOTFILES_ROOT}/${dir}"/*.sh "${DOTFILES_ROOT}/${dir}"/*."${shell}"
        do
            if [[ "${f##*/}" =~ ^path\.[^.]*$ ]]; then
                path_sh[${#path_sh[*]}]="$f"
                debug "      Add $f ito path.sh..."
            elif [[ "${f##*/}" =~ ^env\.[^.]*$ ]]; then
                env_sh[${#env_sh[*]}]="$f"
                debug "      Add $f ito env.sh..."
            elif [[ "${f##*/}" =~ ^completion\.[^.]*$ ]]; then
                completion_sh[${#completion_sh[*]}]="$f"
                debug "      Add $f ito completion.sh..."
            elif ! [[ "${f##*/}" =~ ^requirements\.[^.]*$ ]]; then
                others_sh[${#others_sh[*]}]="$f"
                debug "      Add $f ito others.sh..."
            else
                debug "      Ignoring $f..."
            fi
        done
    done

    # reset nullglob if original value is false
    [ -z "$orig_nullglob" ] && shopt -u nullglob

    echo "# empty stage or stage1"
    echo 'if [[ -z "$1" ]] || [[ "$1" == stage1 ]]; then'

    echo "    # set paths"
    for f in "${path_sh[@]}"
    do
        echo "    source \"$f\""
    done | sort

    echo
    echo "    # set environments"
    for f in "${env_sh[@]}"
    do
        echo "    source \"$f\""
    done | sort

    echo "fi"
    echo

    echo "# empty stage or stage2"
    echo 'if [[ -z "$1" ]] || [[ "$1" == stage2 ]]; then'

    echo "    # others scripts"
    for f in "${others_sh[@]}"
    do
        echo "    source \"$f\""
    done | sort

    echo
    echo "    # completion scripts"
    for f in "${completion_sh[@]}"
    do
        echo "    source \"$f\""
    done | sort

    echo "fi"
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

    info "Checking disabled directory..."

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
}

generate_files() {
    local -A old_enabled
    local d

    if [ -e "$DOTFILES_LOCAL/enabled.txt" ]
    then
        for d in $( cat "$DOTFILES_LOCAL/enabled.txt" )
        do
            old_enabled["$d"]="0"
        done
    fi

    mkdir -p "$DOTFILES_LOCAL"
    cat /dev/null > "$DOTFILES_LOCAL/enabled.txt"

    for dir in "$@"
    do
        if [ -z "${old_enabled[$dir]+isset}" ]
        then
            info "  Enable ${dir}"
        else
            old_enabled["$d"]="1"
            debug "  Enable ${dir}"
        fi

        if [ "${dir}" == "git" ]
        then
            setup_gitconfig
        elif [ "${dir}" == "taskwarrior" ]
        then
            setup_taskrc
        fi

        echo "${dir}" >> "$DOTFILES_LOCAL/enabled.txt"
    done

    for d in "${old_enabled[@]}"
    do
        if [ "${old_enabled[$d]}" == "0" ]
        then
            info "  Disable ${dir}"
        fi
    done

    generate_script_file "$@"

    local overwrite_all=false backup_all=false skip_all=false

    create_symlinks "${DOTFILES_ROOT}" "links.txt" "$@"
    create_symlinks "${DOTFILES_LOCAL}" "links_local.txt" .
}

get_addtional_paths() {
    local dir=

    for dir in "$@"
    do
        [ -d "${DOTFILES_ROOT}/${dir}/bin" ] && echo "${DOTFILES_ROOT}/${dir}/bin"
    done
}

generate_script_file() {
    local dir= shell= script_name=

    for shell in bash zsh
    do
        script_name="$DOTFILES_LOCAL/boot.${shell}"
        info "Generating ${script_name} for ${shell}"

        cat /dev/null > "$script_name"

        echo -n "export PATH=\$PATH" >> "$script_name"

        for dir in $(get_addtional_paths "$@")
        do
            echo -n ":${dir}" >> "$script_name"
        done
        echo >> "$script_name"
        echo >> "$script_name"

        if [ "$shell" == "zsh" ]
        then

            local zsh_completions=( $(get_zsh_completions "$@") )
            if [ ${#zsh_completions[*]} -gt 0 ]
            then
                echo -n "export fpath=(\$fpath" >> "$script_name"
                for dir in "${zsh_completions[@]}"
                do
                    echo -n " ${DOTFILES_ROOT}/${dir}" >> "$script_name"
                done
                echo ")" >> "$script_name"
                echo >> "$script_name"
                echo >> "$script_name"
            fi

        fi

        generate_source_list $shell "$@" >> "$script_name"
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
" >&2
}

TEMP=$(getopt -o h,t: --long help,apply,target: -- "$@")

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

echo ''

if [ "${DRY_RUN}" = 'yes' ]
then
    echo "!!! DRY RUN !!!"
    echo ''
else
    echo "!!! Apply mode !!!"
    echo ''
fi

if [ -d "${DOTFILES_ROOT}/.git" ]
then
    info 'setup submodules'
    pushd "${DOTFILES_ROOT}" > /dev/null
    git submodule init
    git submodule update
    popd > /dev/null
fi

typeset -a dirs

dirs=( $(get_enabled_dir) )
generate_files "${dirs[@]}"

unset dirs

echo ''
echo '  All installed!'
